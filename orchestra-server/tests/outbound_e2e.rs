//! Self-verification test for the `outbound-c` feature.
//!
//! Starts the orchestra-server's agent listener, builds the `agent-standalone`
//! binary with `outbound-c` + address/secret/certificate pin baked in, spawns
//! it, and verifies it registers with the server.
//!
//! The build step is skipped when `SKIP_BUILD_TEST` is set (e.g. in fast CI
//! loops) to keep the suite quick; the full round-trip can be run explicitly
//! with `cargo test -p orchestra-server --test outbound_e2e`.

use orchestra_server::{
    agent_link, api, audit::AuditLog, config::ServerConfig, state::AppState, tls,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

const SECRET: &str = "outbound-test-secret";
const TOKEN: &str = "outbound-test-token";

// Starts only the agent-facing TCP listener and the HTTPS API on ephemeral
// ports.
async fn start_server(tmp: &tempfile::TempDir) -> (u16, u16, String) {
    let cfg = ServerConfig {
        http_addr: "127.0.0.1:0".parse().unwrap(),
        agent_addr: "127.0.0.1:0".parse().unwrap(),
        agent_shared_secret: SECRET.into(),
        admin_token: TOKEN.into(),
        audit_log_path: tmp.path().join("audit.jsonl"),
        tls_cert_path: None,
        tls_key_path: None,
        static_dir: tmp.path().to_path_buf(),
        ..ServerConfig::default()
    };

    let hmac_key = AuditLog::derive_hmac_key(&cfg.admin_token);
    let audit = Arc::new(AuditLog::open(cfg.audit_log_path.clone(), &hmac_key).unwrap());
    let state = Arc::new(AppState::new(
        audit,
        cfg.admin_token.clone(),
        cfg.command_timeout_secs,
        cfg.clone(),
    ));

    let agent_listener = tokio::net::TcpListener::bind(cfg.agent_addr).await.unwrap();
    let agent_port = agent_listener.local_addr().unwrap().port();
    let agent_cert_fp = {
        let state_a = state.clone();
        let secret = cfg.agent_shared_secret.clone();
        // Generate a proper self-signed cert for the agent TLS listener.
        let (agent_tls, agent_cert_fp) = {
            let cert =
                rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                    .unwrap();
            let cert_pem = cert.cert.pem();
            let key_pem = cert.key_pair.serialize_pem();
            let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
                .filter_map(|r| r.ok())
                .collect();
            let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
                .ok()
                .flatten()
                .unwrap();
            let fp = hex_lower(&Sha256::digest(certs[0].as_ref()));
            let tls = Arc::new(
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .unwrap(),
            );
            (tls, fp)
        };
        tokio::spawn(async move {
            agent_link::serve(state_a, agent_listener, secret, agent_tls)
                .await
                .unwrap();
        });
        agent_cert_fp
    };

    let http_listener = std::net::TcpListener::bind(cfg.http_addr).unwrap();
    http_listener.set_nonblocking(true).unwrap();
    let http_port = http_listener.local_addr().unwrap().port();
    let tls_cfg = tls::build(None, None).await.unwrap();
    let app = api::router(state.clone(), cfg.static_dir.clone());
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(http_listener, tls_cfg)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(150)).await;
    (http_port, agent_port, agent_cert_fp)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

fn build_agent_standalone(
    addr: &str,
    secret: &str,
    cert_fp: &str,
) -> anyhow::Result<std::path::PathBuf> {
    // Locate the workspace root from CARGO_MANIFEST_DIR (which points to the
    // orchestra-server crate during tests) by going two levels up.
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap(); // orchestra/

    let status = std::process::Command::new("cargo")
        .current_dir(workspace_root)
        .args([
            "build",
            "-p",
            "agent",
            "--bin",
            "agent-standalone",
            "--features",
            "outbound-c",
        ])
        .env("ORCHESTRA_C_ADDR", addr)
        .env("ORCHESTRA_C_SECRET", secret)
        .env("ORCHESTRA_C_CERT_FP", cert_fp)
        .status()?;
    if !status.success() {
        anyhow::bail!("cargo build agent-standalone failed");
    }
    let bin = workspace_root.join("target/debug/agent-standalone");
    if !bin.exists() {
        anyhow::bail!("binary not found at {}", bin.display());
    }
    Ok(bin)
}

#[tokio::test]
async fn outbound_agent_connects_and_registers() {
    if std::env::var("SKIP_BUILD_TEST").is_ok() {
        eprintln!("SKIP_BUILD_TEST set; skipping outbound build test");
        return;
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
    let tmp = tempfile::tempdir().unwrap();
    let (_http_port, agent_port, cert_fp) = start_server(&tmp).await;
    let addr = format!("127.0.0.1:{agent_port}");

    // Build the agent with address, secret, and the TLS certificate pin baked in.
    let bin = match build_agent_standalone(&addr, SECRET, &cert_fp) {
        Ok(p) => p,
        Err(e) => {
            panic!("Failed to build agent-standalone: {e:#}");
        }
    };

    // Spawn the agent process; it should connect back automatically.
    let mut child = std::process::Command::new(&bin)
        .env("RUST_LOG", "info")
        .spawn()
        .expect("failed to spawn agent-standalone");

    // Poll the /api/agents endpoint until the agent appears (or timeout).
    let client = http_client();
    let agents_url = format!("https://127.0.0.1:{_http_port}/api/agents");
    let mut found = false;
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if let Ok(r) = client
            .get(&agents_url)
            .header("Authorization", format!("Bearer {TOKEN}"))
            .send()
            .await
        {
            if let Ok(body) = r.json::<serde_json::Value>().await {
                if body.as_array().map(|a| !a.is_empty()).unwrap_or(false) {
                    found = true;
                    break;
                }
            }
        }
    }

    // Clean up the child process before asserting so it doesn't linger.
    let _ = child.kill();

    assert!(found, "outbound agent never appeared in /api/agents");
}
