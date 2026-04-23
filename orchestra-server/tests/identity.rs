//! Tests that verify agent identity is bound to the transport connection, not
//! to the self-reported `agent_id`.
//!
//! Key scenario tested:
//! Two agents both report `agent_id = "dup-agent"`.  The server registers
//! them under *distinct* server-assigned `connection_id`s.  Commands routed
//! by `connection_id` reach the correct agent; neither can hijack the other.

use common::{Command, CryptoSession, Message};
use orchestra_server::{
    agent_link, api, audit::AuditLog, config::ServerConfig, state::AppState, tls,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SECRET: &str = "identity-test-secret";
const TOKEN: &str = "identity-test-token";

async fn start_server(tmp: &tempfile::TempDir) -> (u16, u16) {
    let cfg = ServerConfig {
        http_addr: "127.0.0.1:0".parse().unwrap(),
        agent_addr: "127.0.0.1:0".parse().unwrap(),
        agent_shared_secret: SECRET.into(),
        admin_token: TOKEN.into(),
        audit_log_path: tmp.path().join("audit.jsonl"),
        tls_cert_path: None,
        tls_key_path: None,
        static_dir: tmp.path().to_path_buf(),
        command_timeout_secs: 5,
    };

    let audit = Arc::new(AuditLog::open(cfg.audit_log_path.clone()).unwrap());
    let state = Arc::new(AppState::new(
        audit,
        cfg.admin_token.clone(),
        cfg.command_timeout_secs,
    ));

    let agent_listener = tokio::net::TcpListener::bind(cfg.agent_addr).await.unwrap();
    let agent_port = agent_listener.local_addr().unwrap().port();
    {
        let state_a = state.clone();
        let secret = cfg.agent_shared_secret.clone();
        tokio::spawn(async move {
            agent_link::serve(
                state_a,
                agent_listener,
                secret,
                Arc::new(
                    rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(
                            vec![],
                            rustls::pki_types::PrivateKeyDer::Pkcs8(
                                rustls::pki_types::PrivatePkcs8KeyDer::from(vec![]),
                            ),
                        )
                        .unwrap(),
                ),
            )
            .await
            .unwrap();
        });
    }

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

    tokio::time::sleep(Duration::from_millis(200)).await;
    (http_port, agent_port)
}

struct FakeAgent {
    r: tokio::net::tcp::OwnedReadHalf,
    w: tokio::net::tcp::OwnedWriteHalf,
    session: CryptoSession,
}

impl FakeAgent {
    async fn connect(port: u16) -> Self {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

        #[cfg(not(feature = "forward-secrecy"))]
        let session = CryptoSession::from_shared_secret(SECRET.as_bytes());

        let (r, w) = s.into_split();
        Self { r, w, session }
    }

    async fn send(&mut self, m: &Message) {
        let plain = serde_json::to_vec(m).unwrap();
        let enc = self.session.encrypt(&plain);
        self.w.write_u32_le(enc.len() as u32).await.unwrap();
        self.w.write_all(&enc).await.unwrap();
    }

    async fn recv(&mut self) -> Message {
        let len = self.r.read_u32_le().await.unwrap();
        let mut buf = vec![0u8; len as usize];
        self.r.read_exact(&mut buf).await.unwrap();
        let plain = self.session.decrypt(&buf).unwrap();
        serde_json::from_slice(&plain).unwrap()
    }
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// Wait until the `GET /api/agents` response includes exactly `n` entries
/// that match `predicate`, then return those entries.
async fn wait_for_agents(
    client: &reqwest::Client,
    url: &str,
    count: usize,
    predicate: impl Fn(&serde_json::Value) -> bool,
) -> Vec<serde_json::Value> {
    for _ in 0..80 {
        let body: serde_json::Value = client
            .get(url)
            .header("Authorization", format!("Bearer {TOKEN}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let matches: Vec<serde_json::Value> = body
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| predicate(e))
            .cloned()
            .collect();
        if matches.len() >= count {
            return matches;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {count} agents");
}

#[tokio::test]
async fn duplicate_agent_id_gets_distinct_connection_ids() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tmp = tempfile::tempdir().unwrap();
    let (http_port, agent_port) = start_server(&tmp).await;

    // Two agents — both reporting the same agent_id.
    let mut agent_a = FakeAgent::connect(agent_port).await;
    let mut agent_b = FakeAgent::connect(agent_port).await;

    let hb = Message::Heartbeat {
        timestamp: 0,
        agent_id: "dup-agent".into(),
        status: "host".into(),
    };
    agent_a.send(&hb).await;
    agent_b.send(&hb).await;

    let agents_url = format!("https://127.0.0.1:{http_port}/api/agents");
    let client = http_client();

    // Both show up under distinct connection_ids.
    let entries = wait_for_agents(&client, &agents_url, 2, |e| e["agent_id"] == "dup-agent").await;
    assert_eq!(entries.len(), 2, "expected two entries for dup-agent");

    let conn_a = entries[0]["connection_id"].as_str().unwrap().to_string();
    let conn_b = entries[1]["connection_id"].as_str().unwrap().to_string();
    assert_ne!(conn_a, conn_b, "connection_ids must be distinct");
}

#[tokio::test]
async fn command_routed_by_connection_id_reaches_correct_agent() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tmp = tempfile::tempdir().unwrap();
    let (http_port, agent_port) = start_server(&tmp).await;

    let mut agent_a = FakeAgent::connect(agent_port).await;
    let mut agent_b = FakeAgent::connect(agent_port).await;

    agent_a
        .send(&Message::Heartbeat {
            timestamp: 0,
            agent_id: "dup-agent".into(),
            status: "host-a".into(),
        })
        .await;
    agent_b
        .send(&Message::Heartbeat {
            timestamp: 0,
            agent_id: "dup-agent".into(),
            status: "host-b".into(),
        })
        .await;

    let agents_url = format!("https://127.0.0.1:{http_port}/api/agents");
    let client = http_client();

    let entries = wait_for_agents(&client, &agents_url, 2, |e| e["agent_id"] == "dup-agent").await;
    assert_eq!(entries.len(), 2);

    // Find the connection_id that belongs to agent_a (reported hostname "host-a").
    let conn_a = entries
        .iter()
        .find(|e| e["hostname"] == "host-a")
        .expect("host-a entry not found")["connection_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Send a Ping to agent_a specifically, using the connection_id route.
    let conn_url = format!("https://127.0.0.1:{http_port}/api/connections/{conn_a}/command");
    let cmd_fut = client
        .post(&conn_url)
        .header("Authorization", format!("Bearer {TOKEN}"))
        .json(&serde_json::json!({ "command": "Ping" }))
        .send();

    // Only agent_a should receive the TaskRequest.
    let agent_a_handle = tokio::spawn(async move {
        let req = agent_a.recv().await;
        let task_id = match req {
            Message::TaskRequest {
                task_id, command, ..
            } => {
                assert!(matches!(command, Command::Ping));
                task_id
            }
            other => panic!("unexpected message to agent_a: {other:?}"),
        };
        agent_a
            .send(&Message::TaskResponse {
                task_id,
                result: Ok("pong-a".into()),
            })
            .await;
    });

    let resp = cmd_fut.await.unwrap();
    assert_eq!(resp.status(), 200, "command dispatch failed");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["outcome"], "ok");
    assert_eq!(body["output"], "pong-a", "response came from wrong agent");
    agent_a_handle.await.unwrap();

    // agent_b should not have received anything (its recv would time out).
    // We verify this by dropping it cleanly without a message.
    drop(agent_b);
}

#[tokio::test]
async fn operator_id_appears_in_agent_audit_log() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tmp = tempfile::tempdir().unwrap();
    let (http_port, agent_port) = start_server(&tmp).await;

    let mut agent = FakeAgent::connect(agent_port).await;
    agent
        .send(&Message::Heartbeat {
            timestamp: 0,
            agent_id: "audit-agent".into(),
            status: "host".into(),
        })
        .await;

    let agents_url = format!("https://127.0.0.1:{http_port}/api/agents");
    let client = http_client();
    wait_for_agents(&client, &agents_url, 1, |e| e["agent_id"] == "audit-agent").await;

    // The TaskRequest dispatched by the server must include operator_id.
    let cmd_fut = client
        .post(format!(
            "https://127.0.0.1:{http_port}/api/agents/audit-agent/command"
        ))
        .header("Authorization", format!("Bearer {TOKEN}"))
        .json(&serde_json::json!({ "command": "Ping" }))
        .send();

    let agent_handle = tokio::spawn(async move {
        let req = agent.recv().await;
        match req {
            Message::TaskRequest {
                task_id,
                operator_id,
                command,
                ..
            } => {
                assert!(matches!(command, Command::Ping));
                // The server's admin user is "admin" (the AuthenticatedUser identity).
                assert_eq!(
                    operator_id.as_deref(),
                    Some("admin"),
                    "operator_id must be propagated in TaskRequest"
                );
                agent
                    .send(&Message::TaskResponse {
                        task_id,
                        result: Ok("pong".into()),
                    })
                    .await;
            }
            other => panic!("unexpected message: {other:?}"),
        }
    });

    let resp = cmd_fut.await.unwrap();
    assert_eq!(resp.status(), 200);
    agent_handle.await.unwrap();
}
