# Control Center

The Orchestra Control Center (`orchestra-server`) is the self-hosted management
plane for your agent fleet. It provides an authenticated HTTPS dashboard for
inventory, command dispatch, interactive shell sessions, build automation, and
audit review.

---

## Table of contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [REST API](#rest-api)
- [WebSocket API](#websocket-api)
- [Outbound Agents](#outbound-agents)
- [Interactive Shells](#interactive-shells)
- [Build Queue](#build-queue)
- [Audit Logging](#audit-logging)
- [Forward Secrecy](#forward-secrecy)
- [Identity and Routing](#identity-and-routing)
- [DNS-over-HTTPS Bridge](#dns-over-https-bridge)
- [Hardening for Production](#hardening-for-production)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### Using the quickstart script

```sh
./scripts/quickstart.sh     # Linux / macOS
scripts\quickstart.bat      # Windows
```

The script builds the server, generates TLS material and credentials, writes
`orchestra-server.toml`, and optionally starts the server. See
[QUICKSTART.md](QUICKSTART.md) for the full walkthrough.

### Manual start

```sh
cargo build --release -p orchestra-server

# With a config file:
./target/release/orchestra-server --config orchestra-server.toml

# With CLI overrides for quick testing:
./target/release/orchestra-server \
    --admin-token "$(openssl rand -hex 32)" \
    --agent-secret "$(openssl rand -hex 32)"
```

Then open `https://127.0.0.1:8443/` in a browser.

---

## Architecture

```
+----------------+   TLS + AES-GCM PSK  +----------------------+   HTTPS / WS    +-----------+
|  agent (×N)    | <-----------------> |  orchestra-server    | <-------------> |  browser  |
| (managed host) |   length-prefixed   |  (control center)    |  Bearer token   | dashboard |
+----------------+   bincode frames    +----------+-----------+                 +-----------+
                                                  |
                                                  v
                                       JSONL audit log (append-only, HMAC-signed)
```

| Component | Description |
|-----------|-------------|
| **Agent channel** | TLS to `agent_addr`, followed by `CryptoSession` (AES-256-GCM with HKDF-SHA256 per-message salt derivation). Wire format: `salt(32) ‖ nonce(12) ‖ ciphertext_with_tag`. Serialized with bincode. |
| **Operator channel** | `axum` 0.7 + `axum-server` (`rustls`) serving REST under `/api/*`, WebSocket under `/api/ws`, static dashboard from `static/`. |
| **Authentication** | Static bearer token, constant-time compared. Replace with OIDC/JWT for enterprise deployments. |
| **Audit** | Every command is appended to JSONL file at `audit_log_path`. Agents may also push `AuditEvent` records. |

### Crate layout

| File | Purpose |
|------|---------|
| `src/main.rs` | Binary entry point, CLI, listener bring-up |
| `src/config.rs` | TOML config struct |
| `src/state.rs` | `AppState`, agent registry, pending-task table |
| `src/agent_link.rs` | TLS + AES-GCM agent listener and per-connection driver |
| `src/api.rs` | REST + WebSocket router |
| `src/auth.rs` | Bearer-token middleware |
| `src/audit.rs` | Append-only JSONL audit log (HMAC-SHA256) + broadcast |
| `src/tls.rs` | `RustlsConfig` from PEM or self-signed |
| `src/doh_listener.rs` | DNS-over-HTTPS bridge (optional) |
| `src/build_handler.rs` | Async build queue: job tracking, worker pool, output sandboxing |

---

## Configuration

`orchestra-server.toml`:

### Required fields

```toml
http_addr              = "0.0.0.0:8443"        # Dashboard HTTPS listener
agent_addr             = "0.0.0.0:8444"        # Agent TLS listener
agent_shared_secret    = "<32-bytes-hex>"       # PSK for agent authentication
admin_token            = "<bearer-token>"       # Dashboard + API auth token
audit_log_path         = "/var/log/orchestra/audit.jsonl"
static_dir             = "/usr/share/orchestra-server/static"
command_timeout_secs   = 30
```

### TLS configuration

```toml
# Recommended for production — supply real certificates:
tls_cert_path = "/etc/orchestra/server.crt"
tls_key_path  = "/etc/orchestra/server.key"
```

If omitted, the server generates an in-memory self-signed certificate and logs
a warning. **Do not use self-signed certs in production.**

Generate a self-signed cert for testing:

```sh
./scripts/generate-certs.sh
```

Or manually:

```sh
openssl req -x509 -newkey ed25519 -keyout server.key -out server.pem \
    -days 365 -nodes -subj "/CN=orchestra.local" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

### Build queue (optional)

```toml
builds_output_dir     = "/var/lib/orchestra/builds"
build_retention_days  = 7
max_concurrent_builds = 2
```

### DNS-over-HTTPS bridge (optional)

```toml
doh_enabled         = false
doh_listen_addr     = "0.0.0.0:8053"
doh_domain          = "doh.example.com"
doh_beacon_sentinel = "ORCHESTRA_BEACON"
doh_idle_ip         = "127.0.0.1"
```

When `doh_enabled = true`, agents can tunnel sessions over DNS TXT/A queries
through the `doh_listener` module with IP-based rate limiting and staged
authentication.

### mTLS for agent channel (optional)

```toml
mtls_enabled       = false
mtls_ca_cert_path  = "/etc/orchestra/ca.pem"
mtls_allowed_cns   = ["agent.example.com"]
mtls_allowed_ous   = ["OrchestraAgents"]
```

### Traffic normalization (optional)

```toml
agent_traffic_profile = "none"   # "none" | "enterprise" | "stealth"
```

---

## REST API

All routes under `/api/*` require `Authorization: Bearer <admin_token>`.

### Agent management

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/agents` | List connected agents with `connection_id`, `agent_id`, `hostname`, `last_seen`, `peer`. |
| `POST` | `/api/agents/{agent_id}/command` | Send command by agent's self-reported ID (most-recently-seen on duplicates). |
| `POST` | `/api/connections/{connection_id}/command` | Send command by server-assigned connection ID (unambiguous). |

### Command dispatch

The `Command` JSON shape matches `serde_json::to_value(common::Command)`:

```json
{ "command": "Ping" }
{ "command": "GetSystemInfo" }
{ "command": { "ListDirectory": { "path": "/var/log" } } }
{ "command": { "RunApprovedScript": { "script": "rotate-logs" } } }
{ "command": "StartShell" }
{ "command": { "ShellInput": { "session_id": "...", "data": "ZWNobyBoZWxsbwo=" } } }
```

### Shell sessions

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/agents/{agent_id}/shell` | Open PTY session. Body: `{ "shell": "bash" }`. Returns `{ "session_id": "..." }`. |
| `POST` | `/api/agents/{agent_id}/shell/{sid}/input` | Write to PTY stdin. Body: `{ "data": "<base64>" }`. |
| `GET` | `/api/agents/{agent_id}/shell/{sid}/output` | Poll PTY stdout/stderr buffer. |
| `POST` | `/api/agents/{agent_id}/shell/{sid}/close` | Close PTY session and kill child process. |
| `POST` | `/api/agents/{agent_id}/shell/{sid}/resize` | Resize PTY. Body: `{ "rows": 40, "cols": 120 }`. |
| `GET` | `/api/agents/{agent_id}/shells` | List active shell sessions for an agent. |

### Mesh / P2P topology

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/agents/{agent_id}/command` with `MeshConnect` | Tell agent to establish a peer link. Body: `{ "command": { "MeshConnect": { "target_agent_id": "...", "transport": "tcp", "target_addr": "10.0.0.5:8445" } } }` |
| `POST` | `/api/agents/{agent_id}/command` with `MeshDisconnect` | Close a specific peer link. Body: `{ "command": { "MeshDisconnect": { "target_agent_id": "..." } } }` |
| `POST` | `/api/agents/{agent_id}/command` with `MeshKillSwitch` | Emergency: terminate ALL P2P links, purge routing table, refuse new links. |
| `POST` | `/api/agents/{agent_id}/command` with `MeshQuarantine` | Quarantine a peer. Body: `{ "command": { "MeshQuarantine": { "target_agent_id": "...", "reason": 1 } } }` |
| `POST` | `/api/agents/{agent_id}/command` with `MeshClearQuarantine` | Clear quarantine flag for a peer, allowing reconnection. |
| `POST` | `/api/agents/{agent_id}/command` with `MeshSetCompartment` | Set mesh compartment. Body: `{ "command": { "MeshSetCompartment": { "compartment": "red-team-1" } } }` |

**Mesh command examples:**

```sh
# Connect agent to a peer
curl -sk -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"command":{"MeshConnect":{"target_agent_id":"agent-b","transport":"tcp","target_addr":"10.0.0.5:8445"}}}' \
    "$BASE_URL/api/agents/agent-a/command"

# Emergency kill switch — sever all P2P links
curl -sk -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"command":"MeshKillSwitch"}' \
    "$BASE_URL/api/agents/agent-a/command"

# Quarantine a compromised peer
curl -sk -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"command":{"MeshQuarantine":{"target_agent_id":"agent-c","reason":1}}}' \
    "$BASE_URL/api/agents/agent-a/command"
```

### Audit

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/audit` | Return up to 200 most recent audit events. |

### Build queue

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/build` | Submit async build job. Body: `{ "target": "<triple>", "features": [...] }`. Returns `{ "build_id": "..." }`. |
| `GET` | `/api/build/status/{id}` | Poll job status: `pending` / `running` / `completed` / `failed`. |
| `GET` | `/api/build/{id}/download` | Download completed build artifact (encrypted payload). |

### Using curl

```sh
ADMIN_TOKEN="your-admin-token"
BASE_URL="https://127.0.0.1:8443"

# List agents
curl -sk -H "Authorization: Bearer $ADMIN_TOKEN" "$BASE_URL/api/agents"

# Send Ping
curl -sk -X POST \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"command":"Ping"}' \
    "$BASE_URL/api/agents/<agent_id>/command"

# Get system info
curl -sk -X POST \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"command":"GetSystemInfo"}' \
    "$BASE_URL/api/agents/<agent_id>/command"

# View audit log
curl -sk -H "Authorization: Bearer $ADMIN_TOKEN" "$BASE_URL/api/audit"

# Open shell session
curl -sk -X POST \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"shell":"bash"}' \
    "$BASE_URL/api/agents/<agent_id>/shell"
```

---

## WebSocket API

`GET /api/ws` pushes real-time updates. Authenticated via the
`Sec-WebSocket-Protocol` header (not `Authorization`, since browsers cannot
attach custom headers to WebSocket upgrades).

### Authentication

```javascript
const ws = new WebSocket("wss://host/api/ws", ["bearer." + token]);
```

The server:
1. Extracts the value beginning with `bearer.` from `Sec-WebSocket-Protocol`.
2. Compares against `admin_token` in constant time (`subtle::ConstantTimeEq`).
3. Returns HTTP 401 on mismatch. On success, echoes the subprotocol back.

### Message format

The server pushes JSON messages:

| Type | Content |
|------|---------|
| `agents` | Snapshot of all connected agents — pushed every 2 seconds. |
| `audit` | Live audit event — pushed as each event is recorded. |

---

## Outbound Agents

The `outbound-c` feature compiles the agent into a standalone binary that
dials the Control Center automatically and reconnects on disconnection.

### How it works

1. The Builder sets `ORCHESTRA_C_ADDR`, `ORCHESTRA_C_SECRET`, and optionally
   `ORCHESTRA_C_CERT_FP` as compile-time environment variables during `cargo build`.
2. `option_env!("ORCHESTRA_C_ADDR")` in `agent/src/outbound.rs` captures those
   values as string literals baked into the binary.
3. At runtime the agent connects, sends a `Heartbeat` to register, then runs
   the command loop.
4. On transport error, exponential back-off (1 s → 64 s) and reconnect.

### Building via the Builder

```sh
cargo run --release -p builder -- configure --name prod-agent
# Interactive: select target OS/arch, enter CC address, choose features

cargo run --release -p builder -- build prod-agent
# Output: dist/prod-agent.enc
```

### Building manually

```sh
ORCHESTRA_C_ADDR=10.0.0.5:8444 \
ORCHESTRA_C_SECRET=devsecret \
cargo build -p agent --bin agent-standalone --features outbound-c
```

### Profile fields

```toml
package           = "agent"
bin_name          = "agent-standalone"
features          = ["outbound-c"]
c2_address        = "10.0.0.5:8444"
c_server_secret   = "<same-as-agent_shared_secret>"
server_cert_fingerprint = "<64-hex-sha256>"
```

`c_server_secret` must match `agent_shared_secret` in `orchestra-server.toml`.

### Debug overrides

Debug builds can override baked values at runtime:

```sh
ORCHESTRA_C=10.0.0.5:8444 ORCHESTRA_SECRET=devsecret ./agent-standalone
```

Release builds use the baked values only.

---

## Interactive Shells

Interactive PTY sessions are managed through REST endpoints (not arbitrary
command execution). The agent opens a PTY and streams I/O.

### Flow

1. `POST /api/agents/{id}/shell` → `{ "session_id": "abc" }`
2. `POST /api/agents/{id}/shell/abc/input` with base64-encoded bytes
3. `GET /api/agents/{id}/shell/abc/output` to poll output
4. `POST /api/agents/{id}/command` with `{ "command": { "CloseShell": { "session_id": "abc" } } }`

### Internal design

The agent's `ShellSession` spawns a child process with a PTY, then runs a
dedicated reader thread that fills a shared buffer. `try_read_output()` swaps
the buffer with `std::mem::take` — it never blocks the tokio worker.

---

## Build Queue

The Control Center includes an optional async build queue for on-demand agent
compilation.

### Configuration

```toml
builds_output_dir     = "/var/lib/orchestra/builds"
build_retention_days  = 7
max_concurrent_builds = 2
```

### API

```sh
# Submit a build
curl -sk -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"target":"x86_64-unknown-linux-gnu","features":["outbound-c"]}' \
    "$BASE_URL/api/build"
# → { "build_id": "..." }

# Check status
curl -sk -H "Authorization: Bearer $TOKEN" \
    "$BASE_URL/api/build/status/<build_id>"

# Download artifact
curl -sk -H "Authorization: Bearer $TOKEN" \
    "$BASE_URL/api/build/<build_id>/download" -o agent.enc
```

Build output is sandboxed to the configured `builds_output_dir`.

---

## Audit Logging

Every command dispatched through the API generates an HMAC-SHA256-signed
`AuditEvent`:

| Field | Description |
|-------|-------------|
| `timestamp` | Unix seconds at event creation |
| `agent_id` | Endpoint hostname |
| `user` | Operator identity (from `operator_id` in `TaskRequest`) |
| `action` | Human-readable command description (sensitive data redacted) |
| `details` | Success message or error string |
| `outcome` | `Success` or `Failure` |

The audit log is stored as JSONL at `audit_log_path`. Each entry is paired
with an HMAC-SHA256 tag on the next line. Tampered entries are flagged on read.

Sensitive data (file contents, shell I/O, screenshots) is **never** included
in audit records — replaced with size summaries by `sanitize_result()`.

---

## Forward Secrecy

Enable the `forward-secrecy` feature for ephemeral X25519 key exchange:

```toml
# In agent profile:
features = ["forward-secrecy"]
```

The handshake adds a single round-trip before the command loop:

1. Both sides generate fresh X25519 `EphemeralSecret`.
2. Public keys are exchanged.
3. Shared secret = `X25519(priv, peer_pub)`.
4. Session key = `HKDF-SHA256(shared, SHA-256(PSK), "orchestra-fs-v1")`.
5. All subsequent frames use a `CryptoSession` from `session_key`.

**Guarantee**: even if the PSK is later compromised, recorded sessions cannot
be decrypted because ephemeral key material is never persisted.

---

## Identity and Routing

### Connection IDs

Each TCP connection is assigned a server-controlled `connection_id` (`Uuid::new_v4()`)
before any bytes are exchanged. This UUID is the primary key in the agent registry.

### Agent IDs

The `agent_id` the agent reports in its `Heartbeat` is metadata only. A rogue
agent cannot hijack another agent's registry slot or command channel by
spoofing an `agent_id`.

### Routing

| Use case | Route |
|----------|-------|
| Target by self-reported name | `POST /api/agents/{agent_id}/command` |
| Target specific connection | `POST /api/connections/{connection_id}/command` |

When two agents report the same `agent_id` (e.g., reconnect racing with old
socket cleanup), both entries coexist until the old socket's TCP EOF triggers
cleanup.

### Operator identity

Every REST command includes `operator_id` in the `TaskRequest`:

```json
{
  "TaskRequest": {
    "task_id": "...",
    "command": "Ping",
    "operator_id": "admin"
  }
}
```

Older agents that don't recognise `operator_id` still receive commands
(`#[serde(default)]` — silently ignored).

---

## DNS-over-HTTPS Bridge

When enabled, agents can tunnel sessions over DNS queries:

```toml
doh_enabled         = true
doh_listen_addr     = "0.0.0.0:8053"
doh_domain          = "doh.example.com"
doh_beacon_sentinel = "ORCHESTRA_BEACON"
doh_idle_ip         = "127.0.0.1"
```

- IP-based rate limiting
- Staged authentication
- DNS TXT/A query encoding

---

## Hardening for Production

### TLS

1. **Replace self-signed certificates** — supply real TLS material via
   `tls_cert_path` and `tls_key_path`, or terminate TLS at a reverse proxy.
2. **Pin fingerprints in agents** — set `server_cert_fingerprint` in profiles
   so agents verify the server certificate.
3. **Use mTLS for agents** — enable `mtls_enabled` and configure allowed CNs/OU.

### Authentication

4. **Replace the bearer token with mTLS** for operator access, or place the
   server behind an SSO-aware reverse proxy.
5. **Rotate credentials** — generate new `admin_token` and `agent_shared_secret`
   periodically.

### Audit

6. **Forward the audit log** to your SIEM. JSONL format is one event per line;
   tail and ship.
7. **Verify HMAC integrity** periodically to detect tampered records.

### Network

8. **Restrict `http_addr`** — bind to `127.0.0.1` if using a reverse proxy,
   or to a specific internal interface.
9. **Use firewall rules** to restrict access to `agent_addr` (port 8444) to
   known agent source networks.
10. **Content Security Policy** — the shipped dashboard loads no third-party
    scripts. Pin the CSP if you customise `static/index.html`.

### Build queue

11. **Set `build_retention_days`** to clean up old artifacts.
12. **Restrict `builds_output_dir`** permissions so only the server process
    can write to it.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Agent not appearing in dashboard | Not connected | Check agent logs: `RUST_LOG=debug ./agent-standalone` |
| `connection refused` from agent | Server not listening | Verify `agent_addr` matches profile `c2_address` |
| `AES-GCM authentication failed` | PSK mismatch | Ensure `c_server_secret` matches `agent_shared_secret` |
| TLS handshake failure | Certificate mismatch | Regenerate certs; update `server_cert_fingerprint` in profile |
| WebSocket 401 | Wrong token format | Send as `Sec-WebSocket-Protocol: bearer.<token>` |
| Build queue not processing | Missing config | Add `builds_output_dir` to config |

Verbose logging:

```sh
RUST_LOG=debug,orchestra=trace ./target/release/orchestra-server --config orchestra-server.toml
```

---

## See also

- [QUICKSTART.md](QUICKSTART.md) — Clone to first command
- [ARCHITECTURE.md](ARCHITECTURE.md) — Wire protocol and crypto details
- [FEATURES.md](FEATURES.md) — Complete feature flag reference
- [SECURITY.md](SECURITY.md) — Threat model and hardening checklist
