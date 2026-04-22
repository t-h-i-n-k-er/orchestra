import os
import glob

def fix_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    old1 = "agent_link::serve(state_a, agent_listener, secret)"
    new1 = "agent_link::serve(state_a, agent_listener, secret, Arc::new(rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![], rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(vec![]))).unwrap()))"

    if old1 in content:
        content = content.replace(old1, new1)
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"Fixed {filepath}")

for filepath in glob.glob("orchestra-server/tests/*.rs"):
    fix_file(filepath)

