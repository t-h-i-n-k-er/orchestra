use crate::{CryptoSession, Message, Transport};
use anyhow::Result;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Certificate verifier that pins the server's end-entity certificate by its
/// SHA-256 fingerprint (over the raw DER bytes).
///
/// Configure the expected fingerprint as a 64-character lowercase hex string
/// in `agent.toml` under `server_cert_fingerprint`.  This prevents MITM
/// attacks even when TLS is used without a trusted CA chain.
#[derive(Debug)]
pub struct PinnedCertVerifier {
    expected: [u8; 32],
}

impl PinnedCertVerifier {
    /// Build a verifier from the raw 32-byte fingerprint.
    pub fn new(expected: [u8; 32]) -> Self {
        Self { expected }
    }

    /// Build a verifier from a 64-character lowercase hex fingerprint string.
    /// Returns an error if the string is not exactly 64 valid hex digits.
    pub fn from_hex(hex: &str) -> Result<Self> {
        if hex.len() != 64 {
            anyhow::bail!("certificate fingerprint must be 64 hex characters, got {}", hex.len());
        }
        let mut bytes = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let hi = hex_nibble(chunk[0])?;
            let lo = hex_nibble(chunk[1])?;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Self { expected: bytes })
    }
}

fn hex_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => anyhow::bail!("invalid hex character: {}", b as char),
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fingerprint: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if fingerprint == self.expected {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// **Testing only.** Accepts any server certificate without verification.
/// Using this in production makes the connection vulnerable to MITM attacks.
#[doc(hidden)]
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
    session: CryptoSession,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> TlsTransport<S> {
    pub fn new(stream: S, session: CryptoSession) -> Self {
        Self { stream, session }
    }
}

pub const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> Transport for TlsTransport<S> {
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
        if len > MAX_FRAME_BYTES {
            anyhow::bail!("Frame length {} exceeds maximum allowed {}", len, MAX_FRAME_BYTES);
        }
        let mut buf = vec![0u8; len as usize];
        self.stream.read_exact(&mut buf).await?;
        let decrypted = self.session.decrypt(&buf)?;
        Ok(serde_json::from_slice(&decrypted)?)
    }
}
