# Starting the Orchestra C2 Control Panel

## Local Address

The Orchestra Control Center (C2 panel) is hosted at:

| Service | Address |
|---------|---------|
| **Operator Dashboard (HTTPS)** | **`https://127.0.0.1:8443/`** |
| Agent Listener | `0.0.0.0:8444` |

## Prerequisites

- Rust toolchain (`cargo`) installed
- TLS certificate and key in `secrets/` (self-signed certs can be generated with `scripts/generate-certs.sh`)
- A valid `orchestra-server.toml` config file in the project root

## Steps

### 1. Build the Server Binary

```bash
cargo build --release -p orchestra-server
```

This produces the binary at `target/release/orchestra-server`.

### 2. Ensure Configuration & TLS Certificates Exist

The server requires:
- **Config file** (`orchestra-server.toml`) — specifies bind addresses, admin token, agent shared secret, TLS paths, etc.
- **TLS certificate** (`secrets/server.crt`) and **key** (`secrets/server.key`)

If this is a fresh setup, you can use the quickstart script to generate everything:

```bash
./scripts/quickstart.sh
```

Or generate just the TLS certs:

```bash
./scripts/generate-certs.sh
```

### 3. Start the Server

```bash
./target/release/orchestra-server --config orchestra-server.toml
```

Or use the dev script which builds and starts both the control center and a dev file server:

```bash
./scripts/dev-start.sh
```

### 4. Access the Dashboard

Open your browser and navigate to:

```
https://127.0.0.1:8443/
```

Since the server uses a self-signed TLS certificate, your browser will show a security warning. Accept it to proceed.

### 5. Authenticate

The dashboard requires a bearer token for authentication. The admin token is stored in `orchestra-server.toml` under the `admin_token` field.

### 6. Dashboard Tabs

The dashboard is organized into four tabs:

| Tab | Purpose |
|-----|---------|
| **Dashboard** | Live agent table, 100+ commands across 10 categories |
| **Shell** | Interactive shell relay to selected agent |
| **Builder** | Full agent build form (target, C2 params, feature flags, PE artifact kit) |
| **Audit Log** | Live-updating filtered audit log |

The **Builder tab** includes a "Fetch Pin" button that calls `GET /api/info/fingerprint`
to automatically populate the TLS certificate pin field.

## Configuration Reference

The `orchestra-server.toml` file controls all server behavior:

```toml
http_addr            = "0.0.0.0:8443"       # Dashboard HTTPS address
agent_addr           = "0.0.0.0:8444"       # Agent listener address
agent_shared_secret  = "<base64-secret>"    # Shared secret for agent auth
admin_token          = "<token>"             # Bearer token for dashboard auth
audit_log_path       = "secrets/orchestra-audit.jsonl"
static_dir           = "orchestra-server/static"
tls_cert_path        = "secrets/server.crt"
tls_key_path         = "secrets/server.key"
command_timeout_secs = 30
builds_output_dir    = "builds"             # Output dir for built agent payloads
module_aes_key       = "<base64-32-bytes>"  # Required for production agent builds
# allow_local_builds = true                 # Allow loopback/private IP (local testing)
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Connection refused" | Check that the server process is running and the port is not in use |
| TLS certificate errors | Ensure `secrets/server.crt` and `secrets/server.key` exist and are valid |
| Build jobs fail immediately | Ensure `builds_output_dir` is writable and `module_aes_key` is set |
| Agent fails at startup | Ensure `module_aes_key` is in server config and `allow_local_builds = true` for local IP targets |

