//! Malleable C2 Profile Parser & Schema
//!
//! Implements a complete malleable C2 profile system inspired by Cobalt Strike's
//! `.profile` format, but using TOML for easier parsing in Rust.  The profile
//! controls how the agent shapes its HTTP/DNS C2 traffic to blend in with
//! legitimate network activity.
//!
//! # Profile Structure
//!
//! A malleable profile consists of:
//! - **Global settings**: user agent, jitter, sleep timers, DNS idle IP
//! - **SSL configuration**: certificate pinning, SNI
//! - **HTTP GET transaction**: URI patterns, headers, transforms for checkins
//! - **HTTP POST transaction**: URI patterns, headers, transforms for task output
//! - **DNS beacon configuration**: suffixes, DoH settings
//!
//! # Transforms
//!
//! Each transaction direction (client → server, server → client) supports
//! prepend/append wrappers and a payload transform:
//!
//! | Transform   | Description                              |
//! |-------------|------------------------------------------|
//! | `none`      | No encoding (raw bytes)                  |
//! | `base64`    | Standard Base64                          |
//! | `base64url` | URL-safe Base64                          |
//! | `mask`      | XOR mask encoding with configurable stride|
//! | `netbios`   | NetBIOS encoding (lowercase)             |
//! | `netbiosu`  | NetBIOS encoding (uppercase)             |
//!
//! # Usage
//!
//! ```ignore
//! let profile = MalleableProfile::from_toml(toml_str)?;
//! let get_config = profile.http_get.as_ref().unwrap();
//! let uri = get_config.random_uri();
//! ```

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;

// ── Error types ──────────────────────────────────────────────────────────────

/// Errors that can occur during profile parsing or validation.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("I/O error reading profile: {0}")]
    Io(#[from] std::io::Error),

    #[error("at least one of http_get or http_post must be defined")]
    MissingTransaction,

    #[error("URI list is empty for transaction '{0}'")]
    EmptyUriList(String),

    #[error("invalid transform value '{0}' — expected one of: none, base64, base64url, mask, netbios, netbiosu")]
    InvalidTransform(String),

    #[error("invalid delivery method '{0}' — expected one of: cookie, uri-append, header, body")]
    InvalidDeliveryMethod(String),

    #[error("jitter must be 0–100, got {0}")]
    JitterOutOfRange(u8),

    #[error("placeholder syntax error in '{field}': {detail}")]
    PlaceholderSyntax { field: String, detail: String },
}

// ── Transform type ───────────────────────────────────────────────────────────

/// Payload transform encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransformType {
    None,
    Base64,
    Base64Url,
    Mask,
    Netbios,
    NetbiosU,
}

impl TransformType {
    /// Apply this transform to the input bytes, returning encoded output.
    pub fn encode(&self, input: &[u8]) -> Vec<u8> {
        match self {
            TransformType::None => input.to_vec(),
            TransformType::Base64 => B64.encode(input).into_bytes(),
            TransformType::Base64Url => B64URL.encode(input).into_bytes(),
            TransformType::Mask => mask_encode(input, 0x42), // default mask key
            TransformType::Netbios => netbios_encode(input, false),
            TransformType::NetbiosU => netbios_encode(input, true),
        }
    }

    /// Decode data that was encoded with this transform.
    pub fn decode(&self, input: &[u8]) -> Result<Vec<u8>> {
        match self {
            TransformType::None => Ok(input.to_vec()),
            TransformType::Base64 => B64
                .decode(input)
                .map_err(|e| anyhow!("base64 decode error: {}", e)),
            TransformType::Base64Url => B64URL
                .decode(input)
                .map_err(|e| anyhow!("base64url decode error: {}", e)),
            TransformType::Mask => Ok(mask_decode(input, 0x42)),
            TransformType::Netbios => netbios_decode(input, false),
            TransformType::NetbiosU => netbios_decode(input, true),
        }
    }

    /// Apply this transform with a specific mask stride (used when stride > 0).
    pub fn encode_with_mask_stride(&self, input: &[u8], stride: u32) -> Vec<u8> {
        match self {
            TransformType::Mask if stride > 0 => mask_encode(input, stride as u8),
            other => other.encode(input),
        }
    }

    /// Decode with a specific mask stride.
    pub fn decode_with_mask_stride(&self, input: &[u8], stride: u32) -> Result<Vec<u8>> {
        match self {
            TransformType::Mask if stride > 0 => Ok(mask_decode(input, stride as u8)),
            other => other.decode(input),
        }
    }

    /// Parse from a string (case-insensitive).
    pub fn from_str_ci(s: &str) -> std::result::Result<Self, ProfileError> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Ok(TransformType::None),
            "base64" => Ok(TransformType::Base64),
            "base64url" => Ok(TransformType::Base64Url),
            "mask" => Ok(TransformType::Mask),
            "netbios" => Ok(TransformType::Netbios),
            "netbiosu" => Ok(TransformType::NetbiosU),
            other => Err(ProfileError::InvalidTransform(other.to_string())),
        }
    }
}

impl fmt::Display for TransformType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransformType::None => write!(f, "none"),
            TransformType::Base64 => write!(f, "base64"),
            TransformType::Base64Url => write!(f, "base64url"),
            TransformType::Mask => write!(f, "mask"),
            TransformType::Netbios => write!(f, "netbios"),
            TransformType::NetbiosU => write!(f, "netbiosu"),
        }
    }
}

// ── Delivery method ──────────────────────────────────────────────────────────

/// How metadata or output is delivered within an HTTP transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryMethod {
    Cookie,
    UriAppend,
    Header,
    Body,
}

impl DeliveryMethod {
    pub fn from_str_ci(s: &str) -> std::result::Result<Self, ProfileError> {
        match s.to_ascii_lowercase().as_str() {
            "cookie" => Ok(DeliveryMethod::Cookie),
            "uri-append" => Ok(DeliveryMethod::UriAppend),
            "header" => Ok(DeliveryMethod::Header),
            "body" => Ok(DeliveryMethod::Body),
            other => Err(ProfileError::InvalidDeliveryMethod(other.to_string())),
        }
    }
}

impl fmt::Display for DeliveryMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeliveryMethod::Cookie => write!(f, "cookie"),
            DeliveryMethod::UriAppend => write!(f, "uri-append"),
            DeliveryMethod::Header => write!(f, "header"),
            DeliveryMethod::Body => write!(f, "body"),
        }
    }
}

// ── Configuration structs ────────────────────────────────────────────────────

/// Global profile settings that apply across all transaction types.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// SSL/TLS configuration for C2 connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Transform configuration for a single direction (client or server).
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl HttpTransformConfig {
    /// Apply the full transform pipeline: prepend + encode(payload) + append.
    pub fn apply(&self, payload: &[u8]) -> Vec<u8> {
        let encoded = if self.mask_stride > 0 {
            self.transform.encode_with_mask_stride(payload, self.mask_stride)
        } else {
            self.transform.encode(payload)
        };
        let mut out = Vec::with_capacity(self.prepend.len() + encoded.len() + self.append.len());
        out.extend_from_slice(self.prepend.as_bytes());
        out.extend_from_slice(&encoded);
        out.extend_from_slice(self.append.as_bytes());
        out
    }

    /// Reverse the transform pipeline: strip prepend/append, then decode.
    pub fn reverse(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Strip prepend.
        let pre_bytes = self.prepend.as_bytes();
        let rest = if !pre_bytes.is_empty() && data.len() >= pre_bytes.len() && &data[..pre_bytes.len()] == pre_bytes {
            &data[pre_bytes.len()..]
        } else {
            data
        };

        // Strip append.
        let app_bytes = self.append.as_bytes();
        let core = if !app_bytes.is_empty() && rest.len() >= app_bytes.len() && &rest[rest.len() - app_bytes.len()..] == app_bytes {
            &rest[..rest.len() - app_bytes.len()]
        } else {
            rest
        };

        // Decode the transform.
        if self.mask_stride > 0 {
            self.transform.decode_with_mask_stride(core, self.mask_stride)
        } else {
            self.transform.decode(core)
        }
    }
}

/// URI-append configuration for embedding data in URI query strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UriAppendConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_ampersand")]
    pub separator: String,
    #[serde(default = "default_id_key")]
    pub key: String,
}

fn default_ampersand() -> String {
    "&".to_string()
}

fn default_id_key() -> String {
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

/// Metadata delivery configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataConfig {
    #[serde(default = "default_cookie_delivery")]
    pub delivery: DeliveryMethod,
    #[serde(default = "default_session_key")]
    pub key: String,
    #[serde(default = "default_base64_transform")]
    pub transform: TransformType,
}

fn default_cookie_delivery() -> DeliveryMethod {
    DeliveryMethod::Cookie
}

fn default_session_key() -> String {
    "session".to_string()
}

fn default_base64_transform() -> TransformType {
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

/// Output delivery configuration (for HTTP POST responses).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    #[serde(default = "default_body_delivery")]
    pub delivery: DeliveryMethod,
    #[serde(default = "default_base64_transform")]
    pub transform: TransformType,
}

fn default_body_delivery() -> DeliveryMethod {
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

/// Configuration for a single HTTP transaction (GET or POST).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpTransactionConfig {
    #[serde(default)]
    pub uri: Vec<String>,
    #[serde(default = "default_get_verb")]
    pub verb: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub client: HttpTransformConfig,
    #[serde(default)]
    pub server: HttpTransformConfig,
}

fn default_get_verb() -> String {
    "GET".to_string()
}

impl HttpTransactionConfig {
    /// Select a random URI from the configured list.
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

    /// Build the full set of headers for an outbound request, replacing
    /// `{SESSIONID}` placeholders with the provided session ID.
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

/// DNS beacon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// DNS-over-HTTPS headers configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Top-level profile descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileInfo {
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

/// The complete malleable C2 profile.
///
/// This is the primary data structure that controls how the agent shapes its
/// C2 traffic.  It is deserialized from a TOML configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Parse a malleable profile from a TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, ProfileError> {
        // We need to handle the nested `profile.xxx` namespace. The TOML uses
        // `[profile.global]`, `[profile.http_get]`, etc., but our struct
        // flattens these. We first parse into an intermediate raw struct that
        // mirrors the TOML structure exactly, then convert.
        let raw: RawProfile = toml::from_str(toml_str)?;
        let profile = raw.into_profile()?;
        profile.validate()?;
        Ok(profile)
    }

    /// Load a malleable profile from a file path.
    pub fn from_file(path: &Path) -> Result<Self, ProfileError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }

    /// Validate the profile after parsing.
    pub fn validate(&self) -> std::result::Result<(), ProfileError> {
        // At least one HTTP transaction must be defined.
        if self.http_get.is_none() && self.http_post.is_none() {
            return Err(ProfileError::MissingTransaction);
        }

        // Validate URI lists.
        if let Some(ref get) = self.http_get {
            if get.uri.is_empty() {
                return Err(ProfileError::EmptyUriList("http_get".to_string()));
            }
        }
        if let Some(ref post) = self.http_post {
            if post.uri.is_empty() {
                return Err(ProfileError::EmptyUriList("http_post".to_string()));
            }
        }

        // Validate jitter range.
        if self.global.jitter > 100 {
            return Err(ProfileError::JitterOutOfRange(self.global.jitter));
        }

        // Validate placeholder syntax in headers.
        if let Some(ref get) = self.http_get {
            validate_placeholders(&get.headers, "http_get.headers")?;
        }
        if let Some(ref post) = self.http_post {
            validate_placeholders(&post.headers, "http_post.headers")?;
        }

        Ok(())
    }

    /// Get the effective sleep time with jitter applied.
    ///
    /// Returns a random duration between `sleep_time * (1 - jitter%)` and
    /// `sleep_time * (1 + jitter%)`.
    pub fn jittered_sleep(&self) -> std::time::Duration {
        let base = self.global.sleep_time as f64;
        let jitter_frac = self.global.jitter as f64 / 100.0;
        let factor = 1.0 + (rand::thread_rng().gen_range(-1.0..1.0) * jitter_frac);
        let effective = (base * factor).max(0.0) as u64;
        std::time::Duration::from_secs(effective)
    }

    /// Get the full SNI hostname for TLS connections.
    ///
    /// Returns the configured SNI, or falls back to empty string.
    pub fn sni_hostname(&self) -> &str {
        &self.ssl.sni
    }

    /// Check whether SSL certificate pinning is configured.
    pub fn has_cert_pin(&self) -> bool {
        !self.ssl.cert_pin.is_empty()
    }
}

/// Validate that placeholders like `{SESSIONID}` are syntactically valid.
fn validate_placeholders(
    headers: &HashMap<String, String>,
    context: &str,
) -> std::result::Result<(), ProfileError> {
    for (key, value) in headers {
        let mut chars = value.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '{' {
                // Find the closing brace.
                let mut found_close = false;
                for inner in chars.by_ref() {
                    if inner == '}' {
                        found_close = true;
                        break;
                    }
                    // Reject nested braces.
                    if inner == '{' {
                        return Err(ProfileError::PlaceholderSyntax {
                            field: format!("{}.{}", context, key),
                            detail: "nested opening brace".to_string(),
                        });
                    }
                }
                if !found_close {
                    return Err(ProfileError::PlaceholderSyntax {
                        field: format!("{}.{}", context, key),
                        detail: "unclosed brace".to_string(),
                    });
                }
            }
        }
        // Reject unmatched closing braces.
        let open_count = value.matches('{').count();
        let close_count = value.matches('}').count();
        if open_count != close_count {
            return Err(ProfileError::PlaceholderSyntax {
                field: format!("{}.{}", context, key),
                detail: format!(
                    "brace mismatch: {} opening, {} closing",
                    open_count, close_count
                ),
            });
        }
    }
    Ok(())
}

// ── Raw TOML intermediate ────────────────────────────────────────────────────

/// Intermediate TOML structure that mirrors the `[profile.xxx]` namespace.
///
/// The TOML file uses `[profile.global]`, `[profile.http_get]`, etc.
/// We parse into this first, then flatten into `MalleableProfile`.
#[derive(Debug, Deserialize)]
struct RawProfile {
    profile: RawProfileInner,
}

#[derive(Debug, Deserialize)]
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
    http_get: Option<RawHttpTransaction>,
    #[serde(default)]
    http_post: Option<RawHttpTransaction>,
    #[serde(default)]
    dns: DnsConfig,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RawHttpTransaction {
    #[serde(default)]
    uri: Vec<String>,
    #[serde(default)]
    verb: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    uri_append: Option<UriAppendConfig>,
    #[serde(default)]
    client: HttpTransformConfig,
    #[serde(default)]
    server: HttpTransformConfig,
    #[serde(default)]
    metadata: Option<MetadataConfig>,
    #[serde(default)]
    output: Option<OutputConfig>,
}

impl RawProfile {
    fn into_profile(self) -> Result<MalleableProfile, ProfileError> {
        let inner = self.profile;
        Ok(MalleableProfile {
            profile: ProfileInfo {
                name: inner.name,
                author: inner.author,
                description: inner.description,
            },
            global: inner.global,
            ssl: inner.ssl,
            http_get: inner.http_get.map(|raw| raw.into_config("GET")),
            http_post: inner.http_post.map(|raw| raw.into_config("POST")),
            dns: inner.dns,
        })
    }
}

impl RawHttpTransaction {
    fn into_config(self, default_verb: &str) -> HttpTransactionConfig {
        HttpTransactionConfig {
            uri: self.uri,
            verb: if self.verb.is_empty() {
                default_verb.to_string()
            } else {
                self.verb
            },
            headers: self.headers,
            client: self.client,
            server: self.server,
        }
    }
}

// ── Default profile ──────────────────────────────────────────────────────────

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
                    "/dist/bundle.js".to_string(),
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
            }),
            http_post: Some(HttpTransactionConfig {
                uri: vec![
                    "/api/v2/upload".to_string(),
                    "/cdn/ingest".to_string(),
                    "/api/report".to_string(),
                ],
                verb: "POST".to_string(),
                headers: {
                    let mut m = HashMap::new();
                    m.insert("Content-Type".to_string(), "application/json".to_string());
                    m.insert("Accept".to_string(), "*/*".to_string());
                    m.insert("Origin".to_string(), "https://cdn.example.com".to_string());
                    m
                },
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
            }),
            dns: DnsConfig::default(),
        }
    }
}

// ── Encoding helpers ─────────────────────────────────────────────────────────

/// XOR-mask encode with the given key byte.
fn mask_encode(input: &[u8], key: u8) -> Vec<u8> {
    input.iter().map(|b| b ^ key).collect()
}

/// XOR-mask decode (same operation as encode for XOR).
fn mask_decode(input: &[u8], key: u8) -> Vec<u8> {
    input.iter().map(|b| b ^ key).collect()
}

/// NetBIOS encoding: each byte is split into two nibble characters.
///
/// For lowercase, each nibble `n` becomes `b'a' + n`.
/// For uppercase, each nibble `n` becomes `b'A' + n`.
fn netbios_encode(input: &[u8], uppercase: bool) -> Vec<u8> {
    let base = if uppercase { b'A' } else { b'a' };
    let mut out = Vec::with_capacity(input.len() * 2);
    for &byte in input {
        out.push(base + (byte >> 4));
        out.push(base + (byte & 0x0F));
    }
    out
}

/// NetBIOS decode: two ASCII characters per byte.
fn netbios_decode(input: &[u8], uppercase: bool) -> Result<Vec<u8>> {
    if input.len() % 2 != 0 {
        return Err(anyhow!("netbios input length must be even, got {}", input.len()));
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

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PROFILE: &str = r#"
[profile]
name = "linkedin_profile"
author = "operator"
description = "Mimics LinkedIn HTTPS traffic"

[profile.global]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
jitter = 22
sleep_time = 60
dns_idle = "0.0.0.0"
dns_sleep = 0

[profile.ssl]
enabled = true
cert_pin = ""
ja3_fingerprint = ""
sni = "www.linkedin.com"

[profile.http_get]
uri = ["/search/results/", "/groups/", "/profile/view/", "/jobs/view/"]
verb = "GET"

[profile.http_get.headers]
"Accept" = "text/html,application/xhtml+xml"
"Accept-Language" = "en-US,en;q=0.9"
"Cookie" = "li_at={SESSIONID}; JSESSIONID={SESSIONID}"

[profile.http_get.uri_append]
enabled = true
separator = "&"
key = "id"

[profile.http_get.client]
prepend = "GET /search/results HTTP/1.1\r\nHost: www.linkedin.com\r\n\r\n"
append = "\r\n\r\n"
transform = "base64"
mask_stride = 0

[profile.http_get.server]
prepend = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
append = "\r\n"
transform = "base64"
mask_stride = 0

[profile.http_get.metadata]
delivery = "cookie"
key = "li_at"
transform = "base64"

[profile.http_post]
uri = ["/api/upload", "/share/create", "/feed/update/"]
verb = "POST"

[profile.http_post.headers]
"Content-Type" = "application/x-www-form-urlencoded"
"Accept" = "*/*"
"Cookie" = "li_at={SESSIONID}"

[profile.http_post.client]
prepend = "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n"
append = "\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n"
transform = "base64"

[profile.http_post.server]
prepend = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}"
append = ""
transform = "none"

[profile.http_post.output]
delivery = "body"
transform = "base64"

[profile.dns]
enabled = true
beacon = "a1b2."
get_A = "api."
get_TXT = "search."
post = "upload."
max_txt_size = 252
dns_suffix = "linkedin.com"

[profile.dns.headers]
doh_server = "https://dns.google/dns-query"
doh_method = "POST"
"#;

    #[test]
    fn parse_sample_profile() {
        let profile = MalleableProfile::from_toml(SAMPLE_PROFILE).unwrap();
        assert_eq!(profile.profile.name, "linkedin_profile");
        assert_eq!(profile.profile.author, "operator");
        assert_eq!(profile.global.jitter, 22);
        assert_eq!(profile.global.sleep_time, 60);
        assert!(profile.ssl.enabled);
        assert_eq!(profile.ssl.sni, "www.linkedin.com");

        let get = profile.http_get.as_ref().unwrap();
        assert_eq!(get.uri.len(), 4);
        assert_eq!(get.verb, "GET");
        assert!(get.headers.contains_key("Cookie"));

        let post = profile.http_post.as_ref().unwrap();
        assert_eq!(post.uri.len(), 3);
        assert_eq!(post.verb, "POST");

        assert!(profile.dns.enabled);
        assert_eq!(profile.dns.dns_suffix, "linkedin.com");
    }

    #[test]
    fn default_profile_is_valid() {
        let profile = MalleableProfile::default();
        profile.validate().unwrap();
        assert!(profile.http_get.is_some());
        assert!(profile.http_post.is_some());
    }

    #[test]
    fn reject_missing_transactions() {
        let toml = r#"
[profile]
name = "bad"
[profile.global]
user_agent = "test"
jitter = 0
sleep_time = 60
"#;
        let result = MalleableProfile::from_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("at least one"), "unexpected error: {}", err);
    }

    #[test]
    fn reject_empty_uri_list() {
        let toml = r#"
[profile]
name = "bad"
[profile.global]
user_agent = "test"
jitter = 0
sleep_time = 60
[profile.http_get]
uri = []
verb = "GET"
"#;
        let result = MalleableProfile::from_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty"), "unexpected error: {}", err);
    }

    #[test]
    fn reject_invalid_jitter() {
        let toml = r#"
[profile]
name = "bad"
[profile.global]
user_agent = "test"
jitter = 150
sleep_time = 60
[profile.http_get]
uri = ["/test"]
verb = "GET"
"#;
        let result = MalleableProfile::from_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("jitter"), "unexpected error: {}", err);
    }

    #[test]
    fn reject_nested_brace_placeholder() {
        let toml = r#"
[profile]
name = "bad"
[profile.global]
user_agent = "test"
jitter = 0
sleep_time = 60
[profile.http_get]
uri = ["/test"]
verb = "GET"
[profile.http_get.headers]
"Cookie" = "bad={{nested}}"
"#;
        let result = MalleableProfile::from_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("nested"), "unexpected error: {}", err);
    }

    #[test]
    fn reject_unclosed_brace_placeholder() {
        let toml = r#"
[profile]
name = "bad"
[profile.global]
user_agent = "test"
jitter = 0
sleep_time = 60
[profile.http_get]
uri = ["/test"]
verb = "GET"
[profile.http_get.headers]
"X-Custom" = "value={UNCLOSED"
"#;
        let result = MalleableProfile::from_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unclosed"), "unexpected error: {}", err);
    }

    #[test]
    fn transform_none_roundtrip() {
        let data = b"hello world";
        assert_eq!(TransformType::None.encode(data), data);
        assert_eq!(TransformType::None.decode(data).unwrap(), data);
    }

    #[test]
    fn transform_base64_roundtrip() {
        let data = b"hello world";
        let encoded = TransformType::Base64.encode(data);
        assert_ne!(encoded, data);
        let decoded = TransformType::Base64.decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn transform_base64url_roundtrip() {
        let data = b"\xff\xfe\xfd\xfc";
        let encoded = TransformType::Base64Url.encode(data);
        let decoded = TransformType::Base64Url.decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn transform_mask_roundtrip() {
        let data = b"test data 1234";
        let encoded = TransformType::Mask.encode(data);
        assert_ne!(encoded, data);
        let decoded = TransformType::Mask.decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn transform_netbios_roundtrip() {
        let data = b"\x01\x23\xab\xcd";
        let encoded = TransformType::Netbios.encode(data);
        assert_eq!(encoded.len(), data.len() * 2);
        let decoded = TransformType::Netbios.decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn transform_netbiosu_roundtrip() {
        let data = b"\x01\x23\xab\xcd";
        let encoded = TransformType::NetbiosU.encode(data);
        assert_eq!(encoded.len(), data.len() * 2);
        // Uppercase encoding should use A-P range.
        for &b in &encoded {
            assert!((b'A'..=b'P').contains(&b), "byte {} not in A-P range", b);
        }
        let decoded = TransformType::NetbiosU.decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn http_transform_config_apply_and_reverse() {
        let cfg = HttpTransformConfig {
            prepend: "PREFIX_".to_string(),
            append: "_SUFFIX".to_string(),
            transform: TransformType::Base64,
            mask_stride: 0,
        };
        let payload = b"secret data";
        let wrapped = cfg.apply(payload);
        assert!(wrapped.starts_with(b"PREFIX_"));
        assert!(wrapped.ends_with(b"_SUFFIX"));
        let unwrapped = cfg.reverse(&wrapped).unwrap();
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn http_transform_config_apply_none() {
        let cfg = HttpTransformConfig {
            prepend: String::new(),
            append: String::new(),
            transform: TransformType::None,
            mask_stride: 0,
        };
        let payload = b"raw bytes";
        assert_eq!(cfg.apply(payload), payload);
        assert_eq!(cfg.reverse(payload).unwrap(), payload);
    }

    #[test]
    fn random_uri_returns_valid() {
        let cfg = HttpTransactionConfig {
            uri: vec!["/a".to_string(), "/b".to_string(), "/c".to_string()],
            verb: "GET".to_string(),
            headers: HashMap::new(),
            client: HttpTransformConfig::default(),
            server: HttpTransformConfig::default(),
        };
        for _ in 0..20 {
            let uri = cfg.random_uri();
            assert!(uri == "/a" || uri == "/b" || uri == "/c");
        }
    }

    #[test]
    fn random_uri_empty_returns_slash() {
        let cfg = HttpTransactionConfig {
            uri: vec![],
            verb: "GET".to_string(),
            headers: HashMap::new(),
            client: HttpTransformConfig::default(),
            server: HttpTransformConfig::default(),
        };
        assert_eq!(cfg.random_uri(), "/");
    }

    #[test]
    fn build_headers_replaces_session_id() {
        let cfg = HttpTransactionConfig {
            uri: vec!["/test".to_string()],
            verb: "GET".to_string(),
            headers: {
                let mut m = HashMap::new();
                m.insert("Cookie".to_string(), "sid={SESSIONID}".to_string());
                m
            },
            client: HttpTransformConfig::default(),
            server: HttpTransformConfig::default(),
        };
        let headers = cfg.build_headers("abc123");
        assert_eq!(headers.get("Cookie").unwrap(), "sid=abc123");
    }

    #[test]
    fn jittered_sleep_within_range() {
        let profile = MalleableProfile::default();
        let base_secs = profile.global.sleep_time;
        let jitter_pct = profile.global.jitter as f64 / 100.0;
        let min = (base_secs as f64 * (1.0 - jitter_pct)) as u64;
        let max = (base_secs as f64 * (1.0 + jitter_pct)) as u64;

        for _ in 0..50 {
            let d = profile.jittered_sleep();
            assert!(
                d.as_secs() >= min && d.as_secs() <= max,
                "jittered sleep {} outside [{}, {}]",
                d.as_secs(),
                min,
                max,
            );
        }
    }

    #[test]
    fn transform_type_from_str() {
        assert_eq!(TransformType::from_str_ci("base64").unwrap(), TransformType::Base64);
        assert_eq!(TransformType::from_str_ci("Base64").unwrap(), TransformType::Base64);
        assert_eq!(TransformType::from_str_ci("MASK").unwrap(), TransformType::Mask);
        assert!(TransformType::from_str_ci("invalid").is_err());
    }

    #[test]
    fn delivery_method_from_str() {
        assert_eq!(DeliveryMethod::from_str_ci("cookie").unwrap(), DeliveryMethod::Cookie);
        assert_eq!(DeliveryMethod::from_str_ci("uri-append").unwrap(), DeliveryMethod::UriAppend);
        assert_eq!(DeliveryMethod::from_str_ci("HEADER").unwrap(), DeliveryMethod::Header);
        assert!(DeliveryMethod::from_str_ci("invalid").is_err());
    }

    #[test]
    fn mask_encode_decode_with_stride() {
        let data = b"stride test";
        let encoded = TransformType::Mask.encode_with_mask_stride(data, 13);
        let decoded = TransformType::Mask.decode_with_mask_stride(&encoded, 13).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn netbios_decode_rejects_odd_length() {
        let result = TransformType::Netbios.decode(b"abc");
        assert!(result.is_err());
    }

    #[test]
    fn profile_from_toml_validates() {
        let profile = MalleableProfile::from_toml(SAMPLE_PROFILE).unwrap();
        // Validate should succeed.
        profile.validate().unwrap();
    }

    #[test]
    fn transform_display() {
        assert_eq!(TransformType::Base64.to_string(), "base64");
        assert_eq!(TransformType::None.to_string(), "none");
        assert_eq!(TransformType::NetbiosU.to_string(), "netbiosu");
    }

    #[test]
    fn delivery_method_display() {
        assert_eq!(DeliveryMethod::Cookie.to_string(), "cookie");
        assert_eq!(DeliveryMethod::UriAppend.to_string(), "uri-append");
    }
}
