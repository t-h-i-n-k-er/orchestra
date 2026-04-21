//! TLS transport wrapping any `AsyncRead + AsyncWrite` stream (client or server).
//!
//! Messages are framed with a 4-byte little-endian length prefix and
//! serialized as JSON. TLS provides confidentiality and integrity; no
//! additional AES-GCM layer is needed.

use crate::{Message, Transport};
use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A `Transport` implementation that works over any async TLS stream.
///
/// Construct with a `tokio_rustls::client::TlsStream` or
/// `tokio_rustls::server::TlsStream` (both implement `AsyncRead + AsyncWrite`).
pub struct TlsTransport<S> {
    stream: S,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> TlsTransport<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }
}

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> Transport for TlsTransport<S> {
    async fn send(&mut self, msg: Message) -> Result<()> {
        let payload = serde_json::to_vec(&msg)?;
        let len = payload.len() as u32;
        self.stream.write_u32_le(len).await?;
        self.stream.write_all(&payload).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Message> {
        let len = self.stream.read_u32_le().await?;
        let mut buf = vec![0u8; len as usize];
        self.stream.read_exact(&mut buf).await?;
        Ok(serde_json::from_slice(&buf)?)
    }
}
