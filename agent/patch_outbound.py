import re

path = '/home/replicant/la/agent/src/outbound.rs'
with open(path, 'r') as f:
    data = f.read()

# Replace std::env::var("ORCHESTRA_C") with string_crypt::enc_str!
data = re.sub(
    r'std::env::var\("ORCHESTRA_C"\)',
    r'std::env::var(string_crypt::enc_str!("ORCHESTRA_C"))',
    data
)
data = re.sub(
    r'std::env::var\("ORCHESTRA_SECRET"\)',
    r'std::env::var(string_crypt::enc_str!("ORCHESTRA_SECRET"))',
    data
)

# Also check for NormalizedTransport connect
if 'TlsTransport::new' in data:
    # use NormalizedTransport instead of rustls
    replacement = """
    let session = common::CryptoSession::from_shared_secret(secret.as_bytes());
    
    // Wire NormalizedTransport instead of actual rustls
    let mut tls_transport = common::normalized_transport::NormalizedTransport::connect(
        stream, session, common::normalized_transport::Role::Client
    ).await?;
"""
    # Remove rustls usage block
    # This is tricky with regex, we can just rewrite connect_once.

with open(path, 'w') as f:
    f.write(data)

