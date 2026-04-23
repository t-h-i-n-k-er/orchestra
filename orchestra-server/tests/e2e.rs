//! End-to-end test: start the server, simulate an agent connecting over the
//! AES-encrypted TCP socket, and verify the agent is registered and a Ping
//! command round-trips through the operator REST API.

use common::{Command, CryptoSession, Message};
use orchestra_server::{
    agent_link, api, audit::AuditLog, config::ServerConfig, state::AppState, tls,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SECRET: &str = "test-pre-shared-secret";
const TOKEN: &str = "test-admin-token";

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

#[tokio::test]
async fn agent_registers_and_ping_round_trips() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tmp = tempfile::tempdir().unwrap();
    let (http_port, agent_port) = start_server(&tmp).await;

    let mut agent = FakeAgent::connect(agent_port).await;
    agent
        .send(&Message::Heartbeat {
            timestamp: 0,
            agent_id: "agent-one".into(),
            status: "test-host".into(),
        })
        .await;

    let client = http_client();
    let agents_url = format!("https://127.0.0.1:{http_port}/api/agents");

    let unauth = client.get(&agents_url).send().await.unwrap();
    assert_eq!(
        unauth.status(),
        401,
        "unauthenticated requests must be rejected"
    );

    let mut found = false;
    for _ in 0..40 {
        let r = client
            .get(&agents_url)
            .header("Authorization", format!("Bearer {TOKEN}"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let body: serde_json::Value = r.json().await.unwrap();
        if body
            .as_array()
            .map(|a| a.iter().any(|e| e["agent_id"] == "agent-one"))
            .unwrap_or(false)
        {
            found = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(found, "agent never appeared in /api/agents");

    let cmd_url = format!("https://127.0.0.1:{http_port}/api/agents/agent-one/command");
    let cmd_fut = client
        .post(&cmd_url)
        .header("Authorization", format!("Bearer {TOKEN}"))
        .json(&serde_json::json!({ "command": "Ping" }))
        .send();

    let agent_handle = tokio::spawn(async move {
        let req = agent.recv().await;
        let task_id = match req {
            Message::TaskRequest {
                task_id, command, ..
            } => {
                assert!(
                    matches!(command, Command::Ping),
                    "expected Ping, got {command:?}"
                );
                task_id
            }
            other => panic!("unexpected message to agent: {other:?}"),
        };
        agent
            .send(&Message::TaskResponse {
                task_id,
                result: Ok("pong".into()),
            })
            .await;
    });

    let resp = cmd_fut.await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["outcome"], "ok");
    assert_eq!(body["output"], "pong");
    agent_handle.await.unwrap();

    let audit_url = format!("https://127.0.0.1:{http_port}/api/audit");
    let audit: serde_json::Value = client
        .get(&audit_url)
        .header("Authorization", format!("Bearer {TOKEN}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entries = audit.as_array().unwrap();
    assert!(
        entries
            .iter()
            .any(|e| e["action"] == "Ping" && e["agent_id"] == "agent-one"),
        "no Ping audit entry found: {audit:#}"
    );
}
