import sys
content = open('orchestra-server/src/agent_link.rs').read()

old_use = "use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};"
new_use = "use tokio::io::{ReadHalf, WriteHalf};\nuse tokio_rustls::server::TlsStream;\nuse tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};"
content = content.replace(old_use, new_use)

old_read = '''async fn read_frame(r: &mut OwnedReadHalf, sess: &CryptoSession) -> Result<Message> {
    let len = r.read_u32_le().await?;
    if len > MAX_FRAME_BYTES {
        anyhow::bail!("agent frame too large: {len} bytes");
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    let plain = sess
        .decrypt(&buf)
        .map_err(|e| anyhow::anyhow!("decrypt failed: {e:?}"))?;
    Ok(serde_json::from_slice(&plain)?)
}'''

new_read = '''async fn read_frame<S: AsyncReadExt + Unpin>(r: &mut S, sess: &CryptoSession) -> Result<Message> {
    let len = r.read_u32_le().await?;
    if len > MAX_FRAME_BYTES {
        anyhow::bail!("agent frame too large: {len} bytes");
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    let plain = sess
        .decrypt(&buf)
        .map_err(|e| anyhow::anyhow!("decrypt failed: {e:?}"))?;
    Ok(serde_json::from_slice(&plain)?)
}

async fn read_frame_tls<S: AsyncReadExt + Unpin>(r: &mut S) -> Result<Message> {
    let len = r.read_u32_le().await?;
    if len > MAX_FRAME_BYTES {
        anyhow::bail!("agent frame too large: {len} bytes");
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}'''
content = content.replace(old_read, new_read)

old_write = '''async fn write_frame(w: &mut OwnedWriteHalf, sess: &CryptoSession, msg: &Message) -> Result<()> {
    let plain = serde_json::to_vec(msg)?;
    let enc = sess.encrypt(&plain);
    w.write_u32_le(enc.len() as u32).await?;
    w.write_all(&enc).await?;
    Ok(())
}'''

new_write = '''async fn write_frame<S: AsyncWriteExt + Unpin>(w: &mut S, sess: &CryptoSession, msg: &Message) -> Result<()> {
    let plain = serde_json::to_vec(msg)?;
    let enc = sess.encrypt(&plain);
    w.write_u32_le(enc.len() as u32).await?;
    w.write_all(&enc).await?;
    Ok(())
}

async fn write_frame_tls<S: AsyncWriteExt + Unpin>(w: &mut S, msg: &Message) -> Result<()> {
    let plain = serde_json::to_vec(msg)?;
    w.write_u32_le(plain.len() as u32).await?;
    w.write_all(&plain).await?;
    Ok(())
}'''
content = content.replace(old_write, new_write)


old_run = '''pub async fn run(state: Arc<AppState>, addr: std::net::SocketAddr, secret: String) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "agent listener bound");
    serve(state, listener, secret).await
}

/// Drive a pre-bound listener. Useful for tests that want an ephemeral port.
pub async fn serve(state: Arc<AppState>, listener: TcpListener, secret: String) -> Result<()> {
    loop {
        let (sock, peer) = listener.accept().await?;
        let state_c = state.clone();
        let secret_c = secret.clone();
        // Assign a server-controlled connection ID before touching the agent.
        let connection_id = Uuid::new_v4().to_string();
        tokio::spawn(async move {
            if let Err(e) = handle_agent(
                sock,
                peer.to_string(),
                connection_id.clone(),
                state_c,
                secret_c,
            )
            .await
            {
                tracing::warn!(connection_id = %connection_id, %peer, "agent connection ended: {e}");
            }
        });
    }
}'''

new_run = '''pub async fn run(state: Arc<AppState>, addr: std::net::SocketAddr, secret: String, tls: Arc<rustls::ServerConfig>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "agent listener bound");
    serve(state, listener, secret, tls).await
}

/// Drive a pre-bound listener. Useful for tests that want an ephemeral port.
pub async fn serve(state: Arc<AppState>, listener: TcpListener, secret: String, tls: Arc<rustls::ServerConfig>) -> Result<()> {
    loop {
        let (sock, peer) = listener.accept().await?;
        let state_c = state.clone();
        let secret_c = secret.clone();
        let tls_c = tls.clone();
        // Assign a server-controlled connection ID before touching the agent.
        let connection_id = Uuid::new_v4().to_string();
        tokio::spawn(async move {
            if let Err(e) = handle_agent(
                sock,
                peer.to_string(),
                connection_id.clone(),
                state_c,
                secret_c,
                tls_c,
            )
            .await
            {
                tracing::warn!(connection_id = %connection_id, %peer, "agent connection ended: {e}");
            }
        });
    }
}'''
content = content.replace(old_run, new_run)

old_handle = '''async fn handle_agent(
    mut sock: TcpStream,
    peer: String,
    connection_id: String,
    state: Arc<AppState>,
    secret: String,
) -> Result<()> {
    sock.set_nodelay(true).ok();

    #[cfg(feature = "forward-secrecy")]
    let session = {
        use common::crypto::fs_handshake_server;
        tracing::info!(%peer, "performing forward-secrecy key exchange");
        Arc::new(fs_handshake_server(&mut sock, secret.as_bytes()).await?)
    };

    #[cfg(not(feature = "forward-secrecy"))]
    let session = Arc::new(CryptoSession::from_shared_secret(secret.as_bytes()));

    let (mut r, mut w) = sock.into_split();

    let (tx, mut rx) = mpsc::channel::<Message>(CHANNEL_DEPTH);

    // Writer task drains commands from the API layer onto the wire.
    let sess_w = session.clone();
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = write_frame(&mut w, &sess_w, &msg).await {
                tracing::warn!("agent write error: {e}");
                break;
            }
        }
    });

    // Reader loop runs in the connection task.
    let conn_id = connection_id.clone();
    let mut registered = false;

    loop {
        let msg = match read_frame(&mut r, &session).await {'''

new_handle = '''async fn handle_agent(
    mut sock: TcpStream,
    peer: String,
    connection_id: String,
    state: Arc<AppState>,
    secret: String,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<()> {
    sock.set_nodelay(true).ok();

    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    let mut tls_stream = acceptor.accept(sock).await?;

    let (mut r, mut w) = tokio::io::split(tls_stream);

    let (tx, mut rx) = mpsc::channel::<Message>(CHANNEL_DEPTH);

    // Writer task drains commands from the API layer onto the wire.
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = write_frame_tls(&mut w, &msg).await {
                tracing::warn!("agent write error: {e}");
                break;
            }
        }
    });

    // Reader loop runs in the connection task.
    let conn_id = connection_id.clone();
    let mut registered = false;

    loop {
        let msg = match read_frame_tls(&mut r).await {'''
content = content.replace(old_handle, new_handle)

open('orchestra-server/src/agent_link.rs', 'w').write(content)
