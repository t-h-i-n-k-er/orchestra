use crate::{Message, Transport};
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
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fingerprint: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if fingerprint != self.expected {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        // Reject certificates outside their validity window.
        if let Some((not_before, not_after)) = cert_validity_period(end_entity.as_ref()) {
            let now_secs = now.as_secs() as i64;
            if now_secs < not_before {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::NotValidYet,
                ));
            }
            if now_secs > not_after {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::Expired,
                ));
            }
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
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

/// Parse the X.509 `Validity` interval from a DER-encoded certificate.
/// Returns `(not_before, not_after)` as seconds since the Unix epoch, or
/// `None` when the structure cannot be navigated.
///
/// Handles both `UTCTime` (2-digit year) and `GeneralizedTime` (4-digit year).
fn cert_validity_period(der: &[u8]) -> Option<(i64, i64)> {
    // Minimal DER TLV decoder.
    fn read_len(buf: &[u8], pos: usize) -> Option<(usize, usize)> {
        let first = *buf.get(pos)?;
        if first & 0x80 == 0 {
            Some((pos + 1, first as usize))
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 || pos + 1 + n > buf.len() {
                return None;
            }
            let mut l = 0usize;
            for i in 0..n {
                l = (l << 8) | buf[pos + 1 + i] as usize;
            }
            Some((pos + 1 + n, l))
        }
    }
    fn skip(buf: &[u8], pos: usize) -> Option<usize> {
        let (val, len) = read_len(buf, pos + 1)?;
        Some(val + len)
    }
    fn enter(buf: &[u8], pos: usize, tag: u8) -> Option<usize> {
        if buf.get(pos)? != &tag {
            return None;
        }
        let (val, _) = read_len(buf, pos + 1)?;
        Some(val)
    }
    /// Parse a UTCTime (0x17) or GeneralizedTime (0x18), return Unix seconds.
    fn parse_time(buf: &[u8], pos: usize) -> Option<i64> {
        let tag = *buf.get(pos)?;
        let (val, len) = read_len(buf, pos + 1)?;
        if val + len > buf.len() {
            return None;
        }
        let s = std::str::from_utf8(&buf[val..val + len]).ok()?;
        let s = s.trim_end_matches('Z');
        let (year, rest) = match tag {
            0x17 => {
                // UTCTime: YYMMDDHHMMSS
                if s.len() < 12 {
                    return None;
                }
                let yy: i64 = s[0..2].parse().ok()?;
                (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &s[2..])
            }
            0x18 => {
                // GeneralizedTime: YYYYMMDDHHMMSS
                if s.len() < 14 {
                    return None;
                }
                (s[0..4].parse().ok()?, &s[4..])
            }
            _ => return None,
        };
        if rest.len() < 10 {
            return None;
        }
        let mo: i64 = rest[0..2].parse().ok()?;
        let day: i64 = rest[2..4].parse().ok()?;
        let hr: i64 = rest[4..6].parse().ok()?;
        let mn: i64 = rest[6..8].parse().ok()?;
        let sc: i64 = rest[8..10].parse().ok()?;
        // Gregorian date → days since 1970-01-01 (civil calendar algorithm).
        let y = if mo <= 2 { year - 1 } else { year };
        let m = if mo <= 2 { mo + 9 } else { mo - 3 };
        let era = y.div_euclid(400);
        let yoe = y.rem_euclid(400);
        let doy = (153 * m + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146097 + doe - 719468;
        Some(days * 86400 + hr * 3600 + mn * 60 + sc)
    }

    // Navigate: Certificate → TBSCertificate → (skip fields) → Validity.
    let p = enter(der, 0, 0x30)?; // outer Certificate SEQUENCE
    let p = enter(der, p, 0x30)?; // TBSCertificate SEQUENCE
    // optional [0] version
    let p = if der.get(p)? == &0xa0 { skip(der, p)? } else { p };
    let p = skip(der, p)?; // serialNumber INTEGER
    let p = skip(der, p)?; // signature AlgorithmIdentifier SEQUENCE
    let p = skip(der, p)?; // issuer Name SEQUENCE
    let p = enter(der, p, 0x30)?; // Validity SEQUENCE
    let not_before = parse_time(der, p)?;
    let p = skip(der, p)?;
    let not_after = parse_time(der, p)?;
    Some((not_before, not_after))
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
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> TlsTransport<S> {
    /// Create a new `TlsTransport` wrapping an established TLS stream.
    ///
    /// TLS already provides authenticated encryption, so no additional
    /// application-layer cipher is applied.  Messages are framed with a
    /// 4-byte little-endian length prefix followed by JSON.
    pub fn new(stream: S) -> Self {
        Self { stream }
    }
}

pub const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;

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
        if len > MAX_FRAME_BYTES {
            anyhow::bail!("Frame length {} exceeds maximum allowed {}", len, MAX_FRAME_BYTES);
        }
        let mut buf = vec![0u8; len as usize];
        self.stream.read_exact(&mut buf).await?;
        Ok(serde_json::from_slice(&buf)?)
    }
}
