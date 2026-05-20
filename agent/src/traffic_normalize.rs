//! Traffic normalization: inter-packet jitter, random chunk sizing, and
//! padding to break predictable C2 traffic patterns.
//!
//! Gated behind the `traffic-normalization` feature flag. When disabled,
//! traffic passes through unchanged.

use rand::Rng;
use std::time::Duration;

/// Configuration for traffic normalization.
#[derive(Clone, Debug)]
pub struct TrafficNormalizeConfig {
    /// Minimum inter-packet delay in milliseconds.
    pub min_delay_ms: u64,
    /// Maximum inter-packet delay in milliseconds (jitter band).
    pub max_delay_ms: u64,
    /// Whether to add random trailing padding.
    pub add_padding: bool,
    /// Minimum padding bytes.
    pub min_padding: usize,
    /// Maximum padding bytes.
    pub max_padding: usize,
}

impl Default for TrafficNormalizeConfig {
    fn default() -> Self {
        Self {
            min_delay_ms: 100,
            max_delay_ms: 2500,
            add_padding: true,
            min_padding: 16,
            max_padding: 512,
        }
    }
}

/// Normalize outbound data by optionally adding random padding.
///
/// Returns the modified buffer (which may be larger than the input if
/// padding is enabled).
pub fn normalize_outbound(data: &[u8], cfg: &TrafficNormalizeConfig) -> Vec<u8> {
    if !cfg.add_padding {
        return data.to_vec();
    }

    let mut rng = rand::thread_rng();
    let pad_len = if cfg.max_padding > cfg.min_padding {
        rng.gen_range(cfg.min_padding..=cfg.max_padding)
    } else {
        cfg.min_padding
    };

    let mut out = Vec::with_capacity(data.len() + pad_len);
    out.extend_from_slice(data);
    // Append random padding bytes.
    let pad_start = out.len();
    out.resize(out.len() + pad_len, 0);
    rng.fill(&mut out[pad_start..]);
    out
}

/// Strip trailing random padding added by `normalize_outbound`.
///
/// This is called on the receiver side before decryption. Since we don't
/// know the original length a priori, this implementation assumes the
/// caller knows the expected plaintext length (e.g. from the decrypt
/// result), or that the encryption layer handles framing.
///
/// For now this is a no-op: padding is stripped by the encryption layer
/// which correctly returns only the plaintext. This function exists as a
/// placeholder for future header-based length prefixing.
pub fn strip_padding(data: &[u8], _cfg: &TrafficNormalizeConfig) -> Vec<u8> {
    // Padding is stripped by the encryption layer (decrypt returns only plaintext).
    // This function exists as a placeholder for future non-encrypted normalization
    // contexts (e.g., raw ICMP padding where there is no encryption layer).
    // For now, skip the allocation and return the data as-is — the encryption
    // layer already handled decryption and padding removal.
    data.to_vec()
}

/// Compute a jittered inter-packet delay.
pub fn jitter_delay(cfg: &TrafficNormalizeConfig) -> Duration {
    let mut rng = rand::thread_rng();
    let ms = if cfg.max_delay_ms > cfg.min_delay_ms {
        rng.gen_range(cfg.min_delay_ms..=cfg.max_delay_ms)
    } else {
        cfg.min_delay_ms
    };
    Duration::from_millis(ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_adds_padding() {
        let cfg = TrafficNormalizeConfig {
            add_padding: true,
            min_padding: 16,
            max_padding: 32,
            ..Default::default()
        };
        let data = b"hello";
        let out = normalize_outbound(data, &cfg);
        assert!(out.len() >= data.len() + 16);
        assert!(out.len() <= data.len() + 32);
        // Original data must be a prefix.
        assert_eq!(&out[..data.len()], data);
    }

    #[test]
    fn test_normalize_no_padding() {
        let cfg = TrafficNormalizeConfig {
            add_padding: false,
            ..Default::default()
        };
        let data = b"hello";
        let out = normalize_outbound(data, &cfg);
        assert_eq!(out, data);
    }

    #[test]
    fn test_jitter_delay_in_range() {
        let cfg = TrafficNormalizeConfig {
            min_delay_ms: 100,
            max_delay_ms: 200,
            ..Default::default()
        };
        for _ in 0..100 {
            let d = jitter_delay(&cfg);
            assert!(d.as_millis() >= 100);
            assert!(d.as_millis() <= 200);
        }
    }
}
