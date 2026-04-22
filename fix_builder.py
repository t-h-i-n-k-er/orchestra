import re

with open("builder/src/main.rs", "r") as f:
    code = f.read()

# Replace encryption handling
code = re.sub(
    r'let \(enc_key, hmac_key\) = profile\.encryption_keys\(\)\?;',
    r'let (enc_key, _hmac_key) = profile.encryption_keys()?;',
    code
)

code = re.sub(
    r'common::crypto::encrypt_aes_gcm\(&final_agent_bytes, &enc_key, &hmac_key\)\?;',
    r'common::CryptoSession::from_shared_secret(&enc_key).encrypt(&final_agent_bytes);',
    code
)

with open("builder/src/main.rs", "w") as f:
    f.write(code)

