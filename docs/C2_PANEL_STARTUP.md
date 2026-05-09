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

### 1. Fix Compilation Errors (if needed)

The `orchestra-server` crate may have a few compilation errors in `api.rs` and `main.rs` that need to be resolved before building:

- **`api.rs`** — `authenticate_operator()` returns `Option<(String, Vec<String>)>` (operator ID + permissions tuple), but `ws_sessions.insert()` expects a plain `String`. Fix by destructuring: `if let Some((operator_id, _permissions)) = state.authenticate_operator(&token)`.
- **`api.rs`** — `hash_token()` expects `&str` but `token` is a `String`. Fix by passing `&token`.
- **`api.rs`** — Non-exhaustive `match` in `command_label()`. Fix by adding a wildcard arm `_ => "Unknown"`.
- **`main.rs`** — `allow_insecure_redirector` is a `#[cfg(debug_assertions)]` struct field, but its usage in release mode causes a compile error. Fix by gating the usage with `#[cfg(debug_assertions)]` as well.

### 2. Build the Server Binary

```bash
cargo build --release -p orchestra-server
```

This produces the binary at `target/release/orchestra-server`.

### 3. Ensure Configuration & TLS Certificates Exist

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

### 4. Start the Server

```bash
./target/release/orchestra-server --config orchestra-server.toml
```

Or use the dev script which builds and starts both the control center and a dev file server:

```bash
./scripts/dev-start.sh
```

### 5. Access the Dashboard

Open your browser and navigate to:

```
https://127.0.0.1:8443/
```

Since the server uses a self-signed TLS certificate, your browser will show a security warning. Accept it to proceed.

### 6. Authenticate

The dashboard requires a bearer token for authentication. The admin token is stored in `orchestra-server.toml` under the `admin_token` field.

## Configuration Reference

The `orchestra-server.toml` file controls all server behavior:

```toml
http_addr           = "0.0.0.0:8443"       # Dashboard HTTPS address
agent_addr          = "0.0.0.0:8444"       # Agent listener address
agent_shared_secret = "<base64-secret>"     # Shared secret for agent auth
admin_token         = "<token>"             # Bearer token for dashboard auth
audit_log_path      = "secrets/orchestra-audit.jsonl"
static_dir          = "orchestra-server/static"
tls_cert_path       = "secrets/server.crt"
tls_key_path        = "secrets/server.key"
command_timeout_secs = 30
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Build fails with `non-exhaustive patterns` | Add wildcard match arm in `command_label()` |
| Build fails with `no field allow_insecure_redirector` | Ensure `#[cfg(debug_assertions)]` gates both the field definition and its usage |
| "Connection refused" | Check that the server process is running and the port is not in use |
| TLS certificate errors | Ensure `secrets/server.crt` and `secrets/server.key` exist and are valid |
