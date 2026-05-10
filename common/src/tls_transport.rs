use crate::{Message, Transport};
use anyhow::Result;
use async_trait::async_trait;
use log;
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
            anyhow::bail!(
                "certificate fingerprint must be 64 hex characters, got {}",
                hex.len()
            );
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
        server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fingerprint: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if fingerprint != self.expected {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        // P2-15: Validate SAN/hostname in addition to fingerprint pinning.
        if !verify_cert_hostname(end_entity.as_ref(), server_name) {
            log::warn!(
                "tls_transport: certificate fingerprint matched but hostname validation failed"
            );
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
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

/// P2-15: Verify that the certificate's Subject Alternative Names (or Common Name)
/// match the expected server name.
///
/// Performs a minimal DER parse to extract SAN dNSName entries and compares
/// them against `server_name`.  Falls back to CN matching if no SAN extension
/// is present.  Returns `true` if the name matches, `false` otherwise.
fn verify_cert_hostname(der: &[u8], server_name: &rustls::pki_types::ServerName<'_>) -> bool {
    let expected = match server_name {
        rustls::pki_types::ServerName::DnsName(dns) => dns.as_ref().to_ascii_lowercase(),
        _ => return true, // IP address or other types — skip hostname check
    };

    // Try to extract SANs from the certificate.
    if let Some(sans) = extract_san_dns_names(der) {
        for san in &sans {
            if san == &expected || match_wildcard(san, &expected) {
                return true;
            }
        }
        log::warn!(
            "tls_transport: hostname {} not found in SANs: {:?}",
            expected,
            sans
        );
        return false;
    }

    // No SAN extension — fall back to CN matching.
    if let Some(cn) = extract_common_name(der) {
        if cn == expected || match_wildcard(&cn, &expected) {
            return true;
        }
        log::warn!(
            "tls_transport: hostname {} does not match CN {}",
            expected,
            cn
        );
        return false;
    }

    log::warn!("tls_transport: no SAN or CN found in certificate for hostname validation");
    false
}

/// Match a wildcard pattern like `*.example.com` against `sub.example.com`.
fn match_wildcard(pattern: &str, name: &str) -> bool {
    if !pattern.starts_with("*.") {
        return false;
    }
    let suffix = &pattern[1..]; // e.g., ".example.com"
                                // The name must have exactly one label before the suffix.
    if let Some(dot_pos) = name.find('.') {
        name[dot_pos..] == *suffix
    } else {
        false
    }
}

/// Extract dNSName entries from the Subject Alternative Names extension.
fn extract_san_dns_names(der: &[u8]) -> Option<Vec<String>> {
    // OID for SAN: 2.5.29.17 → 55 1d 11
    let san_oid: &[u8] = &[0x55, 0x1d, 0x11];
    let ext_value = find_extension(der, san_oid)?;

    // The extension value is an OCTET STRING wrapping a GeneralNames SEQUENCE.
    let mut pos = 0usize;
    // Skip OCTET STRING tag + length.
    if ext_value.get(pos)? != &0x04 {
        return None;
    }
    pos += 1;
    let (_, _) = read_der_len(ext_value, pos)?;
    pos = read_der_len(ext_value, pos)?.0;

    // SEQUENCE of GeneralNames.
    if ext_value.get(pos)? != &0x30 {
        return None;
    }
    pos += 1;
    let (_, seq_len) = read_der_len(ext_value, pos)?;
    let seq_end = read_der_len(ext_value, pos)?.0 + seq_len;
    pos = read_der_len(ext_value, pos)?.0;

    let mut names = Vec::new();
    while pos < seq_end.min(ext_value.len()) {
        let tag = *ext_value.get(pos)?;
        pos += 1;
        let (val_start, val_len) = read_der_len(ext_value, pos)?;
        pos = val_start + val_len;
        // dNSName = context tag [2] → 0x82
        if tag == 0x82 {
            if let Ok(s) = std::str::from_utf8(&ext_value[val_start..val_start + val_len]) {
                names.push(s.to_ascii_lowercase());
            }
        }
    }
    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

/// Extract the Common Name from the certificate's Subject field.
fn extract_common_name(der: &[u8]) -> Option<String> {
    // OID for CN: 2.5.4.3 → 55 04 03
    let cn_oid: &[u8] = &[0x55, 0x04, 0x03];
    // Navigate: Certificate → TBSCertificate → Subject → RDN Sequence.
    let p = enter_seq(der, 0)?; // Certificate
    let mut p = enter_seq(der, p)?; // TBSCertificate
                                    // Skip optional [0] version.
    if der.get(p)? == &0xa0 {
        p = skip_tlv(der, p)?;
    }
    p = skip_tlv(der, p)?; // serialNumber
    p = skip_tlv(der, p)?; // signature algorithm
    p = skip_tlv(der, p)?; // issuer
                           // Subject SEQUENCE.
    let subject_end = {
        let (vs, vl) = read_der_len(der, p + 1)?;
        vs + vl
    };
    // Scan for CN OID within the Subject.
    let mut pos = enter_seq(der, p)?;
    while pos < subject_end {
        // Each RDN is a SET.
        if der.get(pos)? != &0x31 {
            pos = skip_tlv(der, pos)?;
            continue;
        }
        let mut inner = enter_seq(der, pos)?;
        let set_end = {
            let (vs, vl) = read_der_len(der, pos + 1)?;
            vs + vl
        };
        while inner < set_end.min(der.len()) {
            // AttributeTypeAndValue SEQUENCE.
            if der.get(inner)? != &0x30 {
                inner = skip_tlv(der, inner)?;
                continue;
            }
            inner += 1;
            let (vs, vl) = read_der_len(der, inner)?;
            let attr_end = vs + vl;
            inner = vs;
            // OID.
            if der.get(inner)? != &0x06 {
                inner = attr_end;
                continue;
            }
            let (oid_start, oid_len) = read_der_len(der, inner + 1)?;
            if &der[oid_start..oid_start + oid_len] == cn_oid {
                inner = oid_start + oid_len;
                // UTF8String or PrintableString value.
                let val_tag = *der.get(inner)?;
                inner += 1;
                let (vs, vl) = read_der_len(der, inner)?;
                if val_tag == 0x0c || val_tag == 0x13 {
                    return std::str::from_utf8(&der[vs..vs + vl])
                        .ok()
                        .map(|s| s.to_ascii_lowercase());
                }
            }
            inner = attr_end;
        }
        pos = set_end;
    }
    None
}

/// Find an extension by OID in the certificate's extensions block.
fn find_extension<'a>(der: &'a [u8], oid: &[u8]) -> Option<&'a [u8]> {
    let p = enter_seq(der, 0)?; // Certificate
    let mut p = enter_seq(der, p)?; // TBSCertificate
                                    // Skip optional [0] version.
    if der.get(p)? == &0xa0 {
        p = skip_tlv(der, p)?;
    }
    p = skip_tlv(der, p)?; // serialNumber
    p = skip_tlv(der, p)?; // signature algorithm
    p = skip_tlv(der, p)?; // issuer
    p = skip_tlv(der, p)?; // validity
    p = skip_tlv(der, p)?; // subject
    p = skip_tlv(der, p)?; // subjectPublicKeyInfo
                           // Optional [3] extensions.
    if der.get(p)? != &0xa3 {
        return None;
    }
    let (ext_start, ext_len) = read_der_len(der, p + 1)?;
    let ext_end = ext_start + ext_len;
    let mut pos = ext_start;
    // Extensions SEQUENCE.
    if der.get(pos)? != &0x30 {
        return None;
    }
    pos += 1;
    let (seq_start, seq_len) = read_der_len(der, pos)?;
    let seq_end = seq_start + seq_len;
    pos = seq_start;
    while pos < seq_end.min(ext_end).min(der.len()) {
        // Each extension is a SEQUENCE.
        if der.get(pos)? != &0x30 {
            pos = skip_tlv(der, pos)?;
            continue;
        }
        pos += 1;
        let (vs, vl) = read_der_len(der, pos)?;
        let ext_seq_end = vs + vl;
        pos = vs;
        // OID.
        if der.get(pos)? != &0x06 {
            pos = ext_seq_end;
            continue;
        }
        let (oid_start, oid_len) = read_der_len(der, pos + 1)?;
        if &der[oid_start..oid_start + oid_len] == oid {
            pos = oid_start + oid_len;
            // Skip optional BOOLEAN (critical).
            if der.get(pos)? == &0x01 {
                pos = skip_tlv(der, pos)?;
            }
            // OCTET STRING value.
            if der.get(pos)? == &0x04 {
                let (val_start, val_len) = read_der_len(der, pos + 1)?;
                return Some(&der[val_start..val_start + val_len]);
            }
        }
        pos = ext_seq_end;
    }
    None
}

fn read_der_len(buf: &[u8], pos: usize) -> Option<(usize, usize)> {
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

fn skip_tlv(buf: &[u8], pos: usize) -> Option<usize> {
    let (val, len) = read_der_len(buf, pos + 1)?;
    Some(val + len)
}

fn enter_seq(buf: &[u8], pos: usize) -> Option<usize> {
    if buf.get(pos)? != &0x30 {
        return None;
    }
    let (val, _) = read_der_len(buf, pos + 1)?;
    Some(val)
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
    let p = if der.get(p)? == &0xa0 {
        skip(der, p)?
    } else {
        p
    };
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
///
/// # Runtime guard (P2-08)
///
/// Every method on this type fires a runtime `debug_assert!` that `cfg!(test)`
/// is true, so a stray production code-path cannot silently bypass certificate
/// verification.  (A `debug_assert` is used so that `--release` builds compiled
/// from test code still pass; the compile-time `#[cfg]` gate remains the
/// primary barrier.)
#[doc(hidden)]
#[derive(Debug)]
#[cfg(any(test, feature = "dangerous-tls"))]
pub struct NoCertificateVerification;

#[cfg(any(test, feature = "dangerous-tls"))]
impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // P2-08: Guard against production use.
        debug_assert!(
            cfg!(test),
            "NoCertificateVerification must never be used outside of test builds"
        );
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        debug_assert!(
            cfg!(test),
            "NoCertificateVerification must never be used outside of test builds"
        );
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        debug_assert!(
            cfg!(test),
            "NoCertificateVerification must never be used outside of test builds"
        );
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
    session: crate::CryptoSession,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> TlsTransport<S> {
    /// Create a new `TlsTransport` wrapping an established TLS stream.
    ///
    /// Even though TLS provides encryption, we apply application-layer
    /// cryptographic framing to ensure defense in depth, matching TcpTransport.
    pub fn new(stream: S, session: crate::CryptoSession) -> Self {
        Self { stream, session }
    }
}

pub const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> Transport for TlsTransport<S> {
    async fn send(&mut self, msg: Message) -> Result<()> {
        let serialized = bincode::serialize(&msg)?;
        let encrypted = self.session.encrypt(&serialized);
        let len = encrypted.len() as u32;
        self.stream.write_u32_le(len).await?;
        self.stream.write_all(&encrypted).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Message> {
        let len = self.stream.read_u32_le().await?;
        if len > MAX_FRAME_BYTES {
            anyhow::bail!(
                "Frame length {} exceeds maximum allowed {}",
                len,
                MAX_FRAME_BYTES
            );
        }
        let mut buffer = vec![0u8; len as usize];
        self.stream.read_exact(&mut buffer).await?;
        let decrypted = self.session.decrypt(&buffer)?;
        Ok(bincode::deserialize(&decrypted)?)
    }
}
