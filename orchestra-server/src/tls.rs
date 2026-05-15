//! TLS configuration for the operator-facing HTTPS listener.
//!
//! If both a cert and key path are configured, those PEM files are loaded.
//! Otherwise a self-signed certificate is generated in-memory at startup
//! (suitable for development / single-tenant deployments behind a real
//! reverse proxy).
//!
//! ## Certificate pinning
//!
//! When an operator-supplied certificate is loaded, this module logs the
//! SHA-256 DER fingerprint at startup.  Use that value as
//! `server_cert_fingerprint` in your agent `agent.toml` to enable TLS
//! certificate pinning on the agent side:
//!
//! ```text
//! # In agent.toml:
//! server_cert_fingerprint = "<hex fingerprint printed at server startup>"
//! ```
//!
//! To compute the fingerprint offline:
//! ```sh
//! openssl x509 -in server.crt -outform DER | sha256sum
//! ```

use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::path::Path;

/// Compute the SHA-256 fingerprint of the first PEM certificate in `pem_bytes`
/// and return it as a lowercase colon-separated hex string.
fn cert_fingerprint(pem_bytes: &[u8]) -> Option<String> {
    // Find the first base64 body between -----BEGIN CERTIFICATE----- markers.
    let text = std::str::from_utf8(pem_bytes).ok()?;
    let start = text.find("-----BEGIN CERTIFICATE-----")?;
    let rest = &text[start + 27..];
    let end = rest.find("-----END CERTIFICATE-----")?;
    let b64: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .ok()?;
    let digest = Sha256::digest(&der);
    Some(
        digest
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(""),
    )
}

pub async fn build(cert: Option<&Path>, key: Option<&Path>, dev_mode: bool) -> Result<RustlsConfig> {
    match (cert, key) {
        (Some(c), Some(k)) => {
            let pem_bytes = std::fs::read(c)
                .with_context(|| format!("reading TLS cert from {}", c.display()))?;
            if let Some(fp) = cert_fingerprint(&pem_bytes) {
                tracing::info!(
                    cert = %c.display(),
                    fingerprint = %fp,
                    "TLS certificate loaded — use this fingerprint as \
                     `server_cert_fingerprint` in agent.toml for pinning"
                );
            }
            RustlsConfig::from_pem_file(c, k).await.with_context(|| {
                format!(
                    "loading TLS material from {} / {}",
                    c.display(),
                    k.display()
                )
            })
        }
        _ => {
            if !dev_mode {
                anyhow::bail!(
                    "FATAL: No TLS certificate configured (tls_cert_path / tls_key_path). \
                     Self-signed certificate generation is disabled in production.\n\
                     Either:\n\
                     1) Set tls_cert_path and tls_key_path in your config to point to a real certificate, or\n\
                     2) Run with --dev to allow ephemeral self-signed certs (development/testing only).\n\
                     Tip: Generate a quick local cert with: scripts/generate-certs.sh"
                );
            }
            tracing::warn!(
                "No TLS cert configured; generating an in-memory self-signed certificate. \
                 For production, terminate TLS at a reverse proxy or supply tls_cert_path/tls_key_path."
            );
            let key_pair = rcgen::KeyPair::generate()
                .map_err(|e| anyhow::anyhow!("rcgen key generation failed: {e}"))?;
            let mut params = rcgen::CertificateParams::new(vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
            ])
            .map_err(|e| anyhow::anyhow!("rcgen params failed: {e}"))?;
            params.is_ca = rcgen::IsCa::NoCa;
            let cert = params.self_signed(&key_pair)
                .map_err(|e| anyhow::anyhow!("rcgen self-signed cert failed: {e}"))?;
            let pem_cert = cert.pem();
            if let Some(fp) = cert_fingerprint(pem_cert.as_bytes()) {
                tracing::info!(
                    fingerprint = %fp,
                    "Self-signed TLS certificate generated — \
                     use this fingerprint as `server_cert_fingerprint` in agent.toml for pinning"
                );
            }
            let pem_key = key_pair.serialize_pem();
            RustlsConfig::from_pem(pem_cert.into_bytes(), pem_key.into_bytes())
                .await
                .context("self-signed RustlsConfig")
        }
    }
}

// ── OID TLV constants (DER-encoded: tag 0x06 + length + OID content) ─────────
// OID 2.5.4.3  CommonName
const OID_CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
// OID 2.5.4.11 OrganizationalUnit
const OID_OU: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x0b];

// ── DER subject field extraction ─────────────────────────────────────────────

/// Search `der` for an X.509 subject attribute identified by its full OID TLV
/// (tag 0x06 + length + OID content) and return the string value of the
/// immediately following UTF8String, PrintableString, or IA5String element.
fn extract_subject_field(der: &[u8], oid_tlv: &[u8]) -> Option<String> {
    let pos = der.windows(oid_tlv.len()).position(|w| w == oid_tlv)?;
    let after = pos + oid_tlv.len();
    if after + 2 > der.len() {
        return None;
    }
    let tag = der[after];
    // Accept UTF8String (0x0C), PrintableString (0x13), IA5String (0x16)
    if !matches!(tag, 0x0C | 0x13 | 0x16) {
        return None;
    }
    let len_byte = der[after + 1] as usize;
    let (str_start, str_len) = if len_byte < 0x80 {
        (after + 2, len_byte)
    } else if len_byte == 0x81 && after + 3 <= der.len() {
        (after + 3, der[after + 2] as usize)
    } else {
        return None;
    };
    if str_start + str_len > der.len() {
        return None;
    }
    String::from_utf8(der[str_start..str_start + str_len].to_vec()).ok()
}

/// Extract the Common Name from a DER-encoded X.509 certificate.
pub fn extract_cn(cert: &rustls::pki_types::CertificateDer<'_>) -> Option<String> {
    extract_subject_field(cert.as_ref(), OID_CN)
}

/// Extract the first Organizational Unit from a DER-encoded certificate.
fn extract_ou(cert: &rustls::pki_types::CertificateDer<'_>) -> Option<String> {
    extract_subject_field(cert.as_ref(), OID_OU)
}

// ── Minimal PEM parsers ───────────────────────────────────────────────────────

fn parse_pem_certs(
    pem_bytes: &[u8],
) -> anyhow::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    use anyhow::Context as _;
    let text = std::str::from_utf8(pem_bytes).context("PEM is not valid UTF-8")?;
    let mut certs = Vec::new();
    let mut rest = text;
    while let Some(s) = rest.find("-----BEGIN CERTIFICATE-----") {
        let body = &rest[s + "-----BEGIN CERTIFICATE-----".len()..];
        let e = body
            .find("-----END CERTIFICATE-----")
            .context("malformed PEM: missing END CERTIFICATE")?;
        let b64: String = body[..e].chars().filter(|c| !c.is_whitespace()).collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .context("decoding PEM certificate base64")?;
        certs.push(rustls::pki_types::CertificateDer::from(der));
        rest = &body[e + "-----END CERTIFICATE-----".len()..];
    }
    Ok(certs)
}

fn parse_pem_key(pem_bytes: &[u8]) -> anyhow::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    use anyhow::Context as _;
    use rustls::pki_types::{
        PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    };
    let text = std::str::from_utf8(pem_bytes).context("key PEM is not valid UTF-8")?;
    const VARIANTS: &[(&str, &str, &str)] = &[
        (
            "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----",
            "pkcs8",
        ),
        (
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
            "pkcs1",
        ),
        (
            "-----BEGIN EC PRIVATE KEY-----",
            "-----END EC PRIVATE KEY-----",
            "sec1",
        ),
    ];
    for &(begin, end, variant) in VARIANTS {
        if let Some(s) = text.find(begin) {
            let body = &text[s + begin.len()..];
            if let Some(e) = body.find(end) {
                let b64: String = body[..e].chars().filter(|c| !c.is_whitespace()).collect();
                let der = base64::engine::general_purpose::STANDARD
                    .decode(&b64)
                    .context("decoding PEM key base64")?;
                return Ok(match variant {
                    "pkcs8" => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)),
                    "pkcs1" => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)),
                    "sec1" => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der)),
                    _ => unreachable!(),
                });
            }
        }
    }
    anyhow::bail!("no supported private key format found in PEM data")
}

// ── CN/OU-restricting client certificate verifier ────────────────────────────

/// Wraps a `WebPkiClientVerifier` and additionally enforces CN/OU allow-lists
/// and optional CRL-based revocation checking (P2-16).
#[derive(Debug)]
pub struct CnOuVerifier {
    inner: std::sync::Arc<dyn rustls::server::danger::ClientCertVerifier>,
    allowed_cns: Vec<String>,
    allowed_ous: Vec<String>,
    /// Revoked certificate serial numbers (hex-encoded, lowercase).  Loaded
    /// from the CRL PEM at startup and can be refreshed at runtime via
    /// `POST /api/p2p/reload-crl`.  Protected by an RwLock so the TLS
    /// handshake path (read) is not blocked by a concurrent reload (write).
    revoked_serials: std::sync::RwLock<Vec<String>>,
}

impl rustls::server::danger::ClientCertVerifier for CnOuVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Delegate chain trust to WebPkiClientVerifier first.
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;

        // CN restriction.
        if !self.allowed_cns.is_empty() {
            let cn = extract_cn(end_entity)
                .ok_or_else(|| rustls::Error::General("client cert CN extraction failed".into()))?;
            if !self.allowed_cns.iter().any(|a| *a == cn) {
                return Err(rustls::Error::General(
                    format!("client cert CN '{cn}' not in mtls_allowed_cns").into(),
                ));
            }
        }

        // OU restriction.
        if !self.allowed_ous.is_empty() {
            let ou = extract_ou(end_entity)
                .ok_or_else(|| rustls::Error::General("client cert OU extraction failed".into()))?;
            if !self.allowed_ous.iter().any(|a| *a == ou) {
                return Err(rustls::Error::General(
                    format!("client cert OU '{ou}' not in mtls_allowed_ous").into(),
                ));
            }
        }

        // P2-16: CRL-based revocation check.  If a CRL is loaded, reject
        // any client certificate whose serial number appears in the list.
        if let Ok(serial) = extract_cert_serial(end_entity) {
            let revoked = self
                .revoked_serials
                .read()
                .unwrap_or_else(|p| p.into_inner());
            if revoked.iter().any(|r| *r == serial) {
                return Err(rustls::Error::General(
                    format!("client cert serial {serial} is revoked (CRL)").into(),
                ));
            }
        }

        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Replace the in-memory CRL serial list on a concrete CnOuVerifier.
/// Called from the reload endpoint.
pub fn reload_crl_on_verifier(verifier: &CnOuVerifier, pem_path: &Path) -> anyhow::Result<usize> {
    let serials = load_crl_serials(pem_path)?;
    let count = serials.len();
    let mut guard = verifier
        .revoked_serials
        .write()
        .unwrap_or_else(|p| p.into_inner());
    *guard = serials;
    Ok(count)
}

/// Parse a PEM-encoded X.509 CRL and extract all revoked certificate serial
/// numbers as lowercase hex strings.
fn load_crl_serials(pem_path: &Path) -> anyhow::Result<Vec<String>> {
    let pem_bytes = std::fs::read(pem_path)
        .with_context(|| format!("reading CRL from {}", pem_path.display()))?;
    let text = std::str::from_utf8(&pem_bytes).context("CRL PEM is not valid UTF-8")?;
    let mut serials = Vec::new();
    let mut rest = text;
    while let Some(s) = rest.find("-----BEGIN X509 CRL-----") {
        let body = &rest[s + "-----BEGIN X509 CRL-----".len()..];
        let e = body
            .find("-----END X509 CRL-----")
            .context("malformed CRL PEM: missing END marker")?;
        let b64: String = body[..e].chars().filter(|c| !c.is_whitespace()).collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .context("decoding CRL PEM base64")?;
        serials.extend(parse_crl_der_serials(&der));
        rest = &body[e + "-----END X509 CRL-----".len()..];
    }
    tracing::info!(path = %pem_path.display(), count = serials.len(), "CRL loaded");
    Ok(serials)
}

/// Extract revoked serial numbers from a DER-encoded X.509 v2 CRL.
///
/// Minimal ASN.1 parsing: walks the TBSCertList looking for SEQUENCE { serial,
/// revocationDate } entries.  The CRL structure is:
///
/// ```text
/// SEQUENCE {                          -- CertificateList
///   SEQUENCE {                        -- TBSCertList
///     ...
///     SEQUENCE { serial INTEGER, ... }  -- revokedCertificates entries
///   }
///   ...
/// }
/// ```
fn parse_crl_der_serials(der: &[u8]) -> Vec<String> {
    let mut serials = Vec::new();
    // We scan for INTEGER tags (0x02) preceded by SEQUENCE tags (0x30) that
    // appear to be inside the revokedCertificates portion.  A simple heuristic
    // is sufficient: we look for patterns where a SEQUENCE header is followed
    // by an INTEGER (the serial number).
    let mut i = 0;
    while i + 2 < der.len() {
        // Look for SEQUENCE tag
        if der[i] == 0x30 {
            let (seq_len, header_len) = read_asn1_length(&der[i + 1..]);
            let seq_content_start = i + 1 + header_len;
            if seq_content_start < der.len() && der[seq_content_start] == 0x02 {
                // This SEQUENCE starts with an INTEGER — likely a revoked cert entry
                let int_start = seq_content_start + 1;
                let (int_len, int_header_len) = read_asn1_length(&der[int_start..]);
                let value_start = int_start + int_header_len;
                if value_start + int_len <= der.len() {
                    let serial_bytes = &der[value_start..value_start + int_len];
                    let hex: String = serial_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                    // Skip trivially small serials (likely structural, not real serials)
                    if int_len >= 1 && !hex.chars().all(|c| c == '0') {
                        serials.push(hex);
                    }
                }
                i = seq_content_start + seq_len;
                continue;
            }
        }
        i += 1;
    }
    serials
}

/// Read an ASN.1 DER length field starting at offset 0.  Returns (length, header_bytes).
fn read_asn1_length(buf: &[u8]) -> (usize, usize) {
    if buf.is_empty() {
        return (0, 0);
    }
    let first = buf[0] as usize;
    if first < 0x80 {
        (first, 1)
    } else {
        let num_bytes = first & 0x7f;
        if num_bytes == 0 || num_bytes > 4 || num_bytes + 1 > buf.len() {
            return (0, 1);
        }
        let mut len = 0usize;
        for j in 0..num_bytes {
            len = (len << 8) | (buf[1 + j] as usize);
        }
        (len, 1 + num_bytes)
    }
}

/// Extract the serial number from a DER-encoded X.509 certificate as a
/// lowercase hex string.  Used for CRL revocation comparison.
fn extract_cert_serial(cert: &rustls::pki_types::CertificateDer<'_>) -> anyhow::Result<String> {
    let der = cert.as_ref();
    // X.509 certificate DER structure:
    // SEQUENCE {                     -- Certificate
    //   SEQUENCE {                   -- TBSCertificate
    //     [0] EXPLICIT INTEGER       -- version (optional, context tag 0xa0)
    //     INTEGER                    -- serialNumber
    //     ...
    //   }
    // }
    // Outer SEQUENCE
    if der.len() < 4 || der[0] != 0x30 {
        anyhow::bail!("not a valid certificate DER");
    }
    let (outer_len, outer_hl) = read_asn1_length(&der[1..]);
    let _ = outer_len;
    let mut i = 1 + outer_hl;
    // Inner SEQUENCE (TBSCertificate)
    if i >= der.len() || der[i] != 0x30 {
        anyhow::bail!("no TBSCertificate SEQUENCE");
    }
    let (tbs_len, tbs_hl) = read_asn1_length(&der[i + 1..]);
    let _ = tbs_len;
    let tbs_start = i + 1 + tbs_hl;
    i = tbs_start;
    // Version: may be [0] EXPLICIT (0xa0) wrapping an INTEGER, or absent (v1).
    if i < der.len() && der[i] == 0xa0 {
        let (ver_len, ver_hl) = read_asn1_length(&der[i + 1..]);
        i += 1 + ver_hl + ver_len;
    }
    // Serial number INTEGER
    if i >= der.len() || der[i] != 0x02 {
        anyhow::bail!("serial number not found");
    }
    let (sn_len, sn_hl) = read_asn1_length(&der[i + 1..]);
    let sn_start = i + 1 + sn_hl;
    if sn_start + sn_len > der.len() {
        anyhow::bail!("serial number truncated");
    }
    let serial_bytes = &der[sn_start..sn_start + sn_len];
    Ok(serial_bytes.iter().map(|b| format!("{:02x}", b)).collect())
}

// ── mTLS agent-listener config ────────────────────────────────────────────────

/// Build an `Arc<rustls::ServerConfig>` for the **agent-facing** TCP listener
/// with mutual TLS enabled.
///
/// Unlike the operator HTTPS dashboard (which uses [`build`] and does not
/// require a client certificate), the agent channel should require each
/// connecting agent to present a certificate signed by the operator's private
/// CA (`mtls_ca_cert_path`).  An optional CN/OU allow-list provides an
/// additional restriction beyond CA trust.
///
/// Returns an error if `mtls_ca_cert_path`, `tls_cert_path`, or `tls_key_path`
/// are absent in `server_cfg`.  Self-signed certs are not supported with mTLS
/// because agents must pin a stable certificate fingerprint.
/// Build an `Arc<rustls::ServerConfig>` for the **agent-facing** TCP listener
/// with mutual TLS enabled.
///
/// Returns `(ServerConfig, Option<Arc<CnOuVerifier>>)` so the caller can
/// retain a reference to the verifier for runtime CRL reload (P2-16).
pub fn build_agent_tls_config(
    server_cfg: &crate::config::ServerConfig,
) -> anyhow::Result<(
    std::sync::Arc<rustls::ServerConfig>,
    Option<std::sync::Arc<CnOuVerifier>>,
)> {
    use anyhow::Context as _;

    // ── 1. Load CA certificate(s) ─────────────────────────────────────────
    let ca_path = server_cfg.mtls_ca_cert_path.as_ref().ok_or_else(|| {
        anyhow::anyhow!("mtls_enabled = true requires mtls_ca_cert_path to be set")
    })?;
    let ca_pem = std::fs::read(ca_path)
        .with_context(|| format!("reading mTLS CA cert from {}", ca_path.display()))?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in parse_pem_certs(&ca_pem)? {
        roots
            .add(cert)
            .context("adding CA cert to mTLS root store")?;
    }
    if roots.is_empty() {
        anyhow::bail!(
            "no certificates found in mtls_ca_cert_path {}",
            ca_path.display()
        );
    }

    // ── 2. Build client cert verifier ─────────────────────────────────────
    let wv = rustls::server::WebPkiClientVerifier::builder(std::sync::Arc::new(roots))
        .build()
        .map_err(|e| anyhow::anyhow!("WebPkiClientVerifier build: {e:?}"))?;

    let cnou_verifier: Option<std::sync::Arc<CnOuVerifier>> = if !server_cfg
        .mtls_allowed_cns
        .is_empty()
        || !server_cfg.mtls_allowed_ous.is_empty()
        || server_cfg.mtls_crl_path.is_some()
    {
        // P2-16: Load CRL serials if a CRL path is configured.
        let revoked_serials = match &server_cfg.mtls_crl_path {
                Some(crl_path) => load_crl_serials(crl_path)
                    .with_context(|| format!(
                        "CRL is configured (mtls_crl_path={}) but could not be loaded; \
                         refusing to start without revocation data to prevent revoked certs from being accepted",
                         crl_path.display()
                    ))?,
                None => Vec::new(),
            };
        Some(std::sync::Arc::new(CnOuVerifier {
            inner: wv.clone(),
            allowed_cns: server_cfg.mtls_allowed_cns.clone(),
            allowed_ous: server_cfg.mtls_allowed_ous.clone(),
            revoked_serials: std::sync::RwLock::new(revoked_serials),
        }))
    } else {
        None
    };

    let verifier: std::sync::Arc<dyn rustls::server::danger::ClientCertVerifier> =
        match &cnou_verifier {
            Some(v) => v.clone() as std::sync::Arc<dyn rustls::server::danger::ClientCertVerifier>,
            None => wv,
        };

    // ── 3. Load server certificate and key ────────────────────────────────
    let cert_path = server_cfg.tls_cert_path.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "mtls_enabled = true requires tls_cert_path \
             (self-signed certs are not stable enough for mTLS agent pinning)"
        )
    })?;
    let key_path = server_cfg
        .tls_key_path
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("mtls_enabled = true requires tls_key_path to be set"))?;

    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("reading server cert from {}", cert_path.display()))?;
    let key_pem = std::fs::read(key_path)
        .with_context(|| format!("reading server key from {}", key_path.display()))?;

    let certs = parse_pem_certs(&cert_pem)?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", cert_path.display());
    }
    let key = parse_pem_key(&key_pem)?;

    // ── 4. Assemble ServerConfig ──────────────────────────────────────────
    let cfg = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .context("building rustls ServerConfig with mTLS client verification")?;

    tracing::info!(
        ca = %ca_path.display(),
        allowed_cns = ?server_cfg.mtls_allowed_cns,
        allowed_ous = ?server_cfg.mtls_allowed_ous,
        crl = ?server_cfg.mtls_crl_path.as_ref().map(|p| p.display()),
        "mTLS enabled on agent listener"
    );

    Ok((std::sync::Arc::new(cfg), cnou_verifier))
}
