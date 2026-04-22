//! WebSocket authentication tests for `/api/ws`.

use common::Message;
use orchestra_server::{
    agent_link, api, audit::AuditLog, config::ServerConfig, state::AppState, tls,
};
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::http::{HeaderValue, Uri};

const SECRET: &str = "ws-test-secret";
const TOKEN: &str = "ws-test-admin-token";

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
            agent_link::serve(state_a, agent_listener, secret, Arc::new(rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![], rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(vec![]))).unwrap()))
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

fn ws_request(
    http_port: u16,
    token: &str,
) -> tokio_tungstenite::tungstenite::handshake::client::Request {
    let uri: Uri = format!("wss://127.0.0.1:{http_port}/api/ws")
        .parse()
        .unwrap();
    let mut req = uri.into_client_request().unwrap();
    let headers = req.headers_mut();
    headers.insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_str(&format!("bearer.{token}")).unwrap(),
    );
    headers.insert(
        "Sec-WebSocket-Key",
        HeaderValue::from_str(&generate_key()).unwrap(),
    );
    headers.insert("Sec-WebSocket-Version", HeaderValue::from_static("13"));
    headers.insert("Connection", HeaderValue::from_static("Upgrade"));
    headers.insert("Upgrade", HeaderValue::from_static("websocket"));
    headers.insert(
        "Host",
        HeaderValue::from_str(&format!("127.0.0.1:{http_port}")).unwrap(),
    );
    req
}

fn insecure_tls_connector() -> tokio_tungstenite::Connector {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    struct NoVerify;
    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
            ]
        }
    }

    let cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    tokio_tungstenite::Connector::Rustls(Arc::new(cfg))
}

#[tokio::test]
async fn ws_rejects_missing_token() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tmp = tempfile::tempdir().unwrap();
    let (http_port, _) = start_server(&tmp).await;

    // Build request *without* the bearer subprotocol.
    let uri: Uri = format!("wss://127.0.0.1:{http_port}/api/ws")
        .parse()
        .unwrap();
    let mut req = uri.into_client_request().unwrap();
    let headers = req.headers_mut();
    headers.insert(
        "Sec-WebSocket-Key",
        HeaderValue::from_str(&generate_key()).unwrap(),
    );
    headers.insert("Sec-WebSocket-Version", HeaderValue::from_static("13"));
    headers.insert("Connection", HeaderValue::from_static("Upgrade"));
    headers.insert("Upgrade", HeaderValue::from_static("websocket"));
    headers.insert(
        "Host",
        HeaderValue::from_str(&format!("127.0.0.1:{http_port}")).unwrap(),
    );

    let res = tokio_tungstenite::connect_async_tls_with_config(
        req,
        None,
        false,
        Some(insecure_tls_connector()),
    )
    .await;
    assert!(res.is_err(), "handshake without token must fail");
}

#[tokio::test]
async fn ws_rejects_invalid_token() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tmp = tempfile::tempdir().unwrap();
    let (http_port, _) = start_server(&tmp).await;

    let req = ws_request(http_port, "wrong-token");
    let res = tokio_tungstenite::connect_async_tls_with_config(
        req,
        None,
        false,
        Some(insecure_tls_connector()),
    )
    .await;
    assert!(res.is_err(), "handshake with wrong token must fail");
}

#[tokio::test]
async fn ws_accepts_valid_token_and_delivers_snapshot() {
    use futures_util::StreamExt;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let tmp = tempfile::tempdir().unwrap();
    let (http_port, agent_port) = start_server(&tmp).await;

    // Register a fake agent so the snapshot has content.
    use common::CryptoSession;
    use tokio::io::AsyncWriteExt;
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", agent_port))
        .await
        .unwrap();
    let session = CryptoSession::from_shared_secret(SECRET.as_bytes());
    let hb = Message::Heartbeat {
        timestamp: 0,
        agent_id: "ws-agent".into(),
        status: "host".into(),
    };
    let plain = serde_json::to_vec(&hb).unwrap();
    let enc = session.encrypt(&plain);
    s.write_u32_le(enc.len() as u32).await.unwrap();
    s.write_all(&enc).await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    let req = ws_request(http_port, TOKEN);
    let (mut ws, _resp) = tokio_tungstenite::connect_async_tls_with_config(
        req,
        None,
        false,
        Some(insecure_tls_connector()),
    )
    .await
    .expect("valid token must produce a successful handshake");

    let msg = tokio::time::timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("snapshot should arrive within timeout")
        .expect("ws stream ended")
        .expect("ws error");

    let text = msg.into_text().expect("expected text frame");
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        parsed["kind"], "agents",
        "expected agents snapshot, got {parsed}"
    );
}
