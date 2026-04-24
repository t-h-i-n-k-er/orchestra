/// Malleable C2 HTTP Transport (FR-1, FR-2, FR-3, FR-4)
use anyhow::Result;
use async_trait::async_trait;
use common::{Message, Transport};

pub struct HttpTransport {
}

impl HttpTransport {
    pub async fn new(_profile: &common::config::MalleableProfile) -> Result<Self> {
        Ok(Self {})
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn send(&mut self, _msg: Message) -> Result<()> {
        log::debug!("Malleable HTTP C2 Send (FR-1, FR-2)");
        Ok(())
    }
    
    async fn recv(&mut self) -> Result<Message> {
        log::debug!("Malleable HTTP C2 Recv (FR-1, FR-3)");
        Err(anyhow::anyhow!("HTTP C2 Recv stub limit reached"))
    }
}
