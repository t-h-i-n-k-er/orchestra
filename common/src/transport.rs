use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{CryptoSession, Message, Transport};

pub struct TcpTransport {
    stream: TcpStream,
    session: CryptoSession,
}

impl TcpTransport {
    pub fn new(stream: TcpStream, session: CryptoSession) -> Self {
        Self { stream, session }
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn send(&mut self, msg: Message) -> Result<()> {
        let serialized = serde_json::to_vec(&msg)?;
        let encrypted = self.session.encrypt(&serialized);
        let len = encrypted.len() as u32;
        self.stream.write_u32_le(len).await?;
        self.stream.write_all(&encrypted).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Message> {
        let len = self.stream.read_u32_le().await?;
        let mut buffer = vec![0; len as usize];
        self.stream.read_exact(&mut buffer).await?;
        let decrypted = self.session.decrypt(&buffer)?;
        let msg: Message = serde_json::from_slice(&decrypted)?;
        Ok(msg)
    }
}
