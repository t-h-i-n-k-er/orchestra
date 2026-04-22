use crate::{Message, Transport};
use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug)]
pub struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

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
