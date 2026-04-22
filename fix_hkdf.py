import re

with open("common/src/lib.rs", "r") as f:
    code = f.read()

old_str = '''    pub fn from_shared_secret(pre_shared_secret: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pre_shared_secret);
        let key_bytes = hasher.finalize();
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        Self {
            cipher: Aes256Gcm::new(key),
        }
    }'''

new_str = '''    pub fn from_shared_secret(pre_shared_secret: &[u8]) -> Self {
        let hk = hkdf::Hkdf::<Sha256>::new(None, pre_shared_secret);
        let mut key_bytes = [0u8; KEY_LEN];
        hk.expand(b"orchestra-aes-gcm", &mut key_bytes)
            .expect("HKDF-SHA256 expand must succeed");
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        Self {
            cipher: Aes256Gcm::new(key),
        }
    }'''

code = code.replace(old_str, new_str)
open("common/src/lib.rs", "w").write(code)
