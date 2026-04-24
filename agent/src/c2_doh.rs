/// DNS-over-HTTPS Transport (FR-5)
use anyhow::Result;
use async_trait::async_trait;
use common::{Message, Transport};

pub struct DohTransport {
}

impl DohTransport {
    pub async fn new(_profile: &common::config::MalleableProfile) -> Result<Self> {
        Ok(Self {})
    }
}

#[async_trait]
impl Transport for DohTransport {
    async fn send(&mut self, _msg: Message) -> Result<()> {
        log::debug!("DNS-over-HTTPS C2 Send (FR-5)");
        Ok(())
    }
    
    async fn recv(&mut self) -> Result<Message> {
        log::debug!("DNS-over-HTTPS C2 Recv (FR-5)");
        Err(anyhow::anyhow!("DoH Recv stub limit reached"))
    }
}
