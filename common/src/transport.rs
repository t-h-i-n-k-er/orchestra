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

pub const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;

#[async_trait]
impl Transport for TcpTransport {
    async fn send(&mut self, msg: Message) -> Result<()> {
        let serialized = bincode::serde::encode_to_vec(&msg, bincode::config::legacy())?;
        let encrypted = self.session.encrypt(&serialized);
        let len = encrypted.len() as u32;
        self.stream.write_u32_le(len).await?;
        self.stream.write_all(&encrypted).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Message> {
        let len = self.stream.read_u32_le().await?;
        if len == 0 {
            anyhow::bail!("zero-length frame rejected");
        }
        if len > MAX_FRAME_BYTES {
            anyhow::bail!(
                "Frame length {} exceeds maximum allowed {}",
                len,
                MAX_FRAME_BYTES
            );
        }
        let mut buffer = vec![0; len as usize];
        self.stream.read_exact(&mut buffer).await?;
        let decrypted = self.session.decrypt(&buffer)?;
        let msg: Message = bincode::serde::decode_from_slice(&decrypted, bincode::config::legacy())
            .map(|(v, _)| v)?;
        Ok(msg)
    }
}
