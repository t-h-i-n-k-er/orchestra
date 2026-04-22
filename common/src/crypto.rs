//! AES-256-GCM bulk-encryption utilities and (when the `forward-secrecy`
//! feature is enabled) an ephemeral X25519 key-exchange handshake.

/// Ephemeral X25519 key-exchange handshake for forward secrecy.
pub mod fs {
    use crate::{CryptoSession, KEY_LEN};
    use anyhow::{Context, Result};
    use hkdf::Hkdf;
    use rand::rngs::OsRng;
    use sha2::Sha256;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use x25519_dalek::{EphemeralSecret, PublicKey};
    use aes_gcm::aead::KeyInit;

    const FS_INFO: &[u8] = b"orchestra-fs-v1";

    fn derive_key(shared_secret: &[u8], psk: &[u8]) -> [u8; KEY_LEN] {
        let salt: [u8; 32] = {
            use sha2::Digest;
            sha2::Sha256::digest(psk).into()
        };
        let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
        let mut key = [0u8; KEY_LEN];
        hk.expand(FS_INFO, &mut key)
            .expect("HKDF-SHA256 expand into 32 bytes always succeeds");
        key
    }

    pub struct EphemeralCryptoSession {
        cipher: aes_gcm::Aes256Gcm,
    }

    impl EphemeralCryptoSession {
        pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
            let mut nonce_bytes = [0u8; 12];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
            let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
            let ciphertext = aes_gcm::aead::Aead::encrypt(&self.cipher, nonce, plaintext).unwrap();
            let mut out = Vec::with_capacity(12 + ciphertext.len());
            out.extend_from_slice(&nonce_bytes);
            out.extend_from_slice(&ciphertext);
            out
        }

        pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
            if ciphertext.len() < 12 {
                return Err(anyhow::anyhow!("Truncated"));
            }
            let (nonce_bytes, body) = ciphertext.split_at(12);
            let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
            aes_gcm::aead::Aead::decrypt(&self.cipher, nonce, body)
                .map_err(|_| anyhow::anyhow!("AuthenticationFailed"))
        }

        fn from_key(key_bytes: [u8; KEY_LEN]) -> Self {
            Self {
                cipher: aes_gcm::Aes256Gcm::new(aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&key_bytes)),
            }
        }
    }

    /// Server side of the X25519 forward-secrecy handshake.
    pub async fn fs_handshake_server<S>(stream: &mut S, psk: &[u8]) -> Result<EphemeralCryptoSession>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let server_secret = EphemeralSecret::random_from_rng(OsRng);
        let server_pub = PublicKey::from(&server_secret);

        let mut client_pub_bytes = [0u8; 32];
        stream
            .read_exact(&mut client_pub_bytes)
            .await
            .context("FS handshake: failed to read client public key")?;

        stream
            .write_all(server_pub.as_bytes())
            .await
            .context("FS handshake: failed to send server public key")?;
        stream.flush().await?;

        let client_pub = PublicKey::from(client_pub_bytes);
        let shared = server_secret.diffie_hellman(&client_pub);
        let key = derive_key(shared.as_bytes(), psk);
        Ok(EphemeralCryptoSession::from_key(key))
    }

    /// Client side of the X25519 forward-secrecy handshake.
    pub async fn fs_handshake_client<S>(stream: &mut S, psk: &[u8]) -> Result<EphemeralCryptoSession>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_pub = PublicKey::from(&client_secret);

        stream
            .write_all(client_pub.as_bytes())
            .await
            .context("FS handshake: failed to send client public key")?;
        stream.flush().await?;

        let mut server_pub_bytes = [0u8; 32];
        stream
            .read_exact(&mut server_pub_bytes)
            .await
            .context("FS handshake: failed to read server public key")?;

        let server_pub = PublicKey::from(server_pub_bytes);
        let shared = client_secret.diffie_hellman(&server_pub);
        let key = derive_key(shared.as_bytes(), psk);
        Ok(EphemeralCryptoSession::from_key(key))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tokio::io::duplex;

        #[tokio::test]
        async fn handshake_produces_matching_sessions() {
            let (mut client_stream, mut server_stream) = duplex(1024);
            let psk = b"test-pre-shared-key";

            let server_fut = tokio::spawn(async move {
                fs_handshake_server(&mut server_stream, psk).await
            });
            let client_session = fs_handshake_client(&mut client_stream, psk)
                .await
                .unwrap();
            let server_session = server_fut.await.unwrap().unwrap();

            let plaintext = b"forward secrecy works";
            let ct = client_session.encrypt(plaintext);
            let recovered = server_session.decrypt(&ct).unwrap();
            assert_eq!(recovered, plaintext);
        }

        #[tokio::test]
        async fn wrong_psk_produces_distinct_keys() {
            let (mut c1, mut s1) = duplex(1024);
            let (mut c2, mut s2) = duplex(1024);

            let srv1 =
                tokio::spawn(async move { fs_handshake_server(&mut s1, b"psk-A").await });
            let srv2 =
                tokio::spawn(async move { fs_handshake_server(&mut s2, b"psk-B").await });

            let cli1 = fs_handshake_client(&mut c1, b"psk-A").await.unwrap();
            let cli2 = fs_handshake_client(&mut c2, b"psk-B").await.unwrap();
            srv1.await.unwrap().unwrap();
            srv2.await.unwrap().unwrap();

            let ct = cli1.encrypt(b"hello");
            assert!(
                cli2.decrypt(&ct).is_err(),
                "different PSKs should produce different session keys"
            );
        }
    }
}
