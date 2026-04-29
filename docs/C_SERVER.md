# Orchestra Control Center (`orchestra-server`)

> Orchestra Control Center is a self-hosted management plane for enterprise
> device orchestration. It fronts a fleet of Orchestra agents and gives
> operators a single authenticated HTTPS dashboard for inventory, command
> dispatch, and audit review.

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

- **Agent channel.** Stock agents use the outbound Control Center path:
   TLS to `agent_addr` (certificate-pinned when configured), followed by
   `common::CryptoSession` (AES-256-GCM with HKDF-SHA256 per-message salt
   derivation, protocol v2 wire format: `salt(32) ‖ nonce(12) ‖ ciphertext_with_tag`)
   and the shared `Message` protocol serialized with **bincode**.
- **DoH bridge (optional).** When `doh_enabled = true`, agents can tunnel
   sessions over DNS TXT/A queries through the `doh_listener` module with
   IP-based rate limiting and staged authentication.
- **Operator channel.** `axum` 0.7 + `axum-server` (`rustls`) serving
  REST under `/api/*`, a WebSocket under `/api/ws`, and the static
  dashboard from `static/`.
- **Authentication.** Static bearer token stored in the server config
  (constant-time compared in `auth::require_bearer`). Replace with
  OIDC/JWT when integrating with an enterprise IdP — see the project
  ROADMAP.
- **Audit.** Every operator-issued command is appended to a JSON-Lines
  file at `audit_log_path`. Agents may also push their own
  `Message::AuditLog` events, which are recorded the same way.

## Crate layout

| File | Purpose |
|------|---------|
| [src/main.rs](../orchestra-server/src/main.rs) | Binary entry point, CLI, listener bring-up |
| [src/config.rs](../orchestra-server/src/config.rs) | TOML config struct |
| [src/state.rs](../orchestra-server/src/state.rs) | `AppState`, agent registry, pending-task table |
| [src/agent_link.rs](../orchestra-server/src/agent_link.rs) | TLS + AES-GCM agent listener and per-connection driver |
| [src/api.rs](../orchestra-server/src/api.rs) | REST + WebSocket router |
| [src/auth.rs](../orchestra-server/src/auth.rs) | Bearer-token middleware |
| [src/audit.rs](../orchestra-server/src/audit.rs) | Append-only JSONL audit log (HMAC-SHA256 signed) + broadcast |
| [src/tls.rs](../orchestra-server/src/tls.rs) | `RustlsConfig` from PEM or self-signed |
| [src/doh_listener.rs](../orchestra-server/src/doh_listener.rs) | DNS-over-HTTPS bridge for agent sessions (optional) |
| [src/build_handler.rs](../orchestra-server/src/build_handler.rs) | Async build queue: job tracking, worker pool, output sandboxing |
| [static/index.html](../orchestra-server/static/index.html) | Dashboard markup |
| [static/app.js](../orchestra-server/static/app.js) | Dashboard client (vanilla JS) |
| [tests/e2e.rs](../orchestra-server/tests/e2e.rs) | End-to-end test: agent + ping round-trip |
| [tests/identity.rs](../orchestra-server/tests/identity.rs) | Identity binding: duplicate `agent_id`, `connection_id` routing, operator audit |
| [tests/ws_auth.rs](../orchestra-server/tests/ws_auth.rs) | WebSocket authentication boundary tests |

## Configuration

`orchestra-server.toml`:

```toml
http_addr = "0.0.0.0:8443"
agent_addr = "0.0.0.0:8444"
agent_shared_secret = "REPLACE-ME-32-bytes-of-entropy"
admin_token = "REPLACE-ME-bearer-token"
audit_log_path = "/var/log/orchestra/audit.jsonl"
static_dir = "/usr/share/orchestra-server/static"
command_timeout_secs = 30

# Optional: PEM TLS material (recommended for production).
# tls_cert_path = "/etc/orchestra/server.crt"
# tls_key_path  = "/etc/orchestra/server.key"

# Optional: Async build queue.
# builds_output_dir     = "/var/lib/orchestra/builds"
# build_retention_days  = 7
# max_concurrent_builds = 2

# Optional: DNS-over-HTTPS bridge for agent sessions.
# doh_enabled         = false
# doh_listen_addr     = "0.0.0.0:8053"
# doh_domain          = "doh.example.com"
# doh_beacon_sentinel = "ORCHESTRA_BEACON"
# doh_idle_ip         = "127.0.0.1"

# Optional: Traffic-normalization profile for agent channel.
# agent_traffic_profile = "none"   # "none" | "enterprise" | "stealth"

# Optional: Mutual TLS for the agent channel.
# mtls_enabled       = false
# mtls_ca_cert_path  = "/etc/orchestra/ca.pem"
# mtls_allowed_cns   = ["agent.example.com"]
# mtls_allowed_ous   = ["OrchestraAgents"]
```

If `tls_cert_path` / `tls_key_path` are omitted, the server logs a
warning and generates an in-memory self-signed certificate. **Do not**
ship that into production — terminate TLS at a reverse proxy or supply
real material.

Run with:

```bash
orchestra-server --config /etc/orchestra/orchestra-server.toml
```

CLI overrides exist for quick local runs:

```bash
orchestra-server \
  --admin-token "$(openssl rand -hex 32)" \
  --agent-secret "$(openssl rand -hex 32)"
```

## REST API

All routes under `/api/*` require `Authorization: Bearer <admin_token>`.

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `GET`  | `/api/agents` | — | List connected agents (`connection_id`, `agent_id`, `hostname`, `last_seen`, `peer`). |
| `POST` | `/api/agents/{agent_id}/command` | `{ "command": <Command> }` | Route by agent's self-reported `agent_id` (most-recently-seen wins on duplicate). |
| `POST` | `/api/connections/{connection_id}/command` | `{ "command": <Command> }` | Unambiguous routing by server-assigned `connection_id` — use this when multiple agents share an `agent_id`. |
| `GET`  | `/api/audit` | — | Return up to 200 most recent audit events. |
| `POST` | `/api/build` | `{ "target": "<triple>", "features": [...] }` | Submit an async build job to the build queue. Returns `{ "build_id": "..." }`. |
| `GET`  | `/api/build/status/{id}` | — | Poll build job status (`pending` / `running` / `completed` / `failed`). |
| `GET`  | `/api/build/{id}/download` | — | Download the completed build artifact (encrypted payload). |
| `POST` | `/api/agents/{agent_id}/shell` | `{ "shell": "bash" }` | Open an interactive PTY session on the agent. Returns `{ "session_id": "..." }`. |
| `POST` | `/api/agents/{agent_id}/shell/{sid}/input` | `{ "data": "<base64>" }` | Write bytes to the PTY session's stdin. |
| `GET`  | `/api/agents/{agent_id}/shell/{sid}/output` | — | Poll the PTY session's stdout/stderr buffer. |
| `GET`  | `/api/ws` | — | WebSocket — pushes `agents` snapshots every 2s and live `audit` events. Authenticated via the `Sec-WebSocket-Protocol` header — see below. |

The `Command` JSON shape matches `serde_json::to_value(common::Command)`.
Examples:

```json
{ "command": "Ping" }
{ "command": "GetSystemInfo" }
{ "command": { "ListDirectory": { "path": "/var/log" } } }
{ "command": { "RunApprovedScript": { "script": "rotate-logs" } } }
{ "command": "StartShell" }
{ "command": { "ShellInput": { "session_id": "...", "data": "ZWNobyBoZWxsbwo=" } } }
```

Interactive shell sessions are managed through `StartShell`, `ShellInput`,
`ShellOutput`, and `CloseShell` commands. The agent opens a PTY and streams
I/O through dedicated REST endpoints (see above). There is no arbitrary
command execution endpoint — shells run through a sandboxed PTY managed by
the agent.

## WebSocket authentication

Browsers cannot attach a custom `Authorization` header to a WebSocket
upgrade request, so `/api/ws` does **not** sit behind the
`require_bearer` middleware. Instead, the dashboard sends the bearer
token in the `Sec-WebSocket-Protocol` handshake header, formatted as
`bearer.<token>`:

```js
new WebSocket("wss://host/api/ws", ["bearer." + token]);
```

Inside `ws_handler` (see [api.rs](../orchestra-server/src/api.rs)) the
server:

1. Reads `Sec-WebSocket-Protocol` and extracts the value beginning with
   `bearer.`.
2. Compares it against `state.admin_token` in **constant time** using
   `subtle::ConstantTimeEq`.
3. On mismatch (or missing protocol) returns **HTTP 401** without
   completing the upgrade.
4. On success, echoes `bearer.<token>` back as the negotiated
   subprotocol so the browser accepts the upgrade, then runs the
   ordinary `ws_loop`.

Coverage lives in [tests/ws_auth.rs](../orchestra-server/tests/ws_auth.rs):
handshakes without a token, with a wrong token, and with the correct
token are exercised end-to-end against a self-signed TLS listener.

## Self-verification

```
cargo test -p orchestra-server --test e2e
```

The test boots the server with self-signed TLS on ephemeral ports,
connects a fake agent over the TLS + AES-GCM agent channel, asserts that
`GET /api/agents` requires auth and lists the agent, sends a `Ping`
through the REST API, has the fake agent reply `pong`, and checks the
audit log contains the resulting entry.

Manual smoke test:

```bash
# Terminal 1
cargo run -p orchestra-server -- \
  --admin-token devtoken --agent-secret devsecret

# Terminal 2 — point a browser at https://127.0.0.1:8443
# (accept the self-signed cert warning), enter "devtoken" to sign in.
```

## Outbound agents (`outbound-c`)

The supported packaged deployment model is the **outbound-c** feature. It
compiles the agent into a standalone binary that dials the Control Center
automatically and reconnects on disconnection. The legacy `console` binary is
a protocol-testing client for custom listeners; stock `agent-standalone` does
not expose a direct console listener.

### How it works

1. The Builder sets `ORCHESTRA_C_ADDR=<host:port>`,
   `ORCHESTRA_C_SECRET=<psk>`, and optionally
   `ORCHESTRA_C_CERT_FP=<sha256-der-fingerprint>` as environment variables
   during `cargo build`.
2. `option_env!("ORCHESTRA_C_ADDR")` in `agent/src/outbound.rs` captures
   those values as compile-time string literals baked into the binary.
3. At runtime the agent connects to the baked address, sends a `Heartbeat` to
   register, then runs the standard command loop. Debug builds may override
   the baked address/secret with `ORCHESTRA_C` and `ORCHESTRA_SECRET`; release
   builds use the baked values.
4. On any transport error the agent sleeps with exponential back-off (1 s → 64 s)
   and reconnects. A clean `Shutdown` command from the server stops the loop.

### Building an outbound agent

**Using the Builder wizard:**

```bash
cargo run --release -p builder -- configure --name prod-linux-outbound
# • Select target OS/arch
# • Enter the Control Center address: 10.0.0.5:8444
# • When asked for features, select outbound-c
# • Enter the pre-shared secret (must match agent_shared_secret in
#   orchestra-server.toml)
cargo run --release -p builder -- build prod-linux-outbound
```

The output is an encrypted `dist/prod-linux-outbound.enc` suitable for the
launcher flow or for your internal deployment packaging.

**Manual (for development/testing):**

```bash
ORCHESTRA_C_ADDR=127.0.0.1:8444 \
ORCHESTRA_C_SECRET=devsecret \
ORCHESTRA_C_CERT_FP=<sha256-der-fingerprint> \
cargo build -p agent --bin agent-standalone --features outbound-c

# Then run it; it connects back to the server immediately:
./target/debug/agent-standalone
```

Debug builds can also override the address at runtime without rebuilding:

```bash
ORCHESTRA_C=10.0.0.5:8444 ORCHESTRA_SECRET=devsecret ./agent-standalone
```

### Profile fields

Add to your `profiles/<name>.toml`:

```toml
package           = "agent"
bin_name          = "agent-standalone"
features          = ["outbound-c"]
c2_address        = "10.0.0.5:8444"   # baked as ORCHESTRA_C_ADDR
c_server_secret   = "REPLACE-ME"      # baked as ORCHESTRA_C_SECRET
server_cert_fingerprint = "<64-hex-sha256>" # baked as ORCHESTRA_C_CERT_FP
```

`c_server_secret` must match `agent_shared_secret` in
`orchestra-server.toml`. If omitted, release builds have no baked secret and
will fail closed; debug builds may supply `ORCHESTRA_SECRET` at runtime for
local testing.

### Self-verification

```bash
cargo test -p orchestra-server --test outbound_e2e
```

This test starts the server on ephemeral ports, compiles `agent-standalone`
with `outbound-c` and the test address baked in, spawns the binary, and
asserts that it appears in `GET /api/agents` within ~12 seconds.

Set `SKIP_BUILD_TEST=1` to skip the `cargo build` step (fast CI runs).

## Agent identity binding

Each TCP connection accepted by the agent listener is assigned a
server-controlled `connection_id` (`Uuid::new_v4()`) before any bytes
are exchanged with the agent.  That UUID is the key used in the agent
registry (`DashMap`); the `agent_id` the agent reports in its
`Heartbeat` is stored as metadata only.

**Security implication:** a rogue agent cannot hijack another agent's
registry slot or command channel by sending a spoofed `agent_id`.  The
worst a rogue agent can do is register under any `agent_id` label while
being tracked under its own, server-assigned `connection_id`.

When two agents report the same `agent_id` (e.g., a reconnect racing
with cleanup of the old socket), the server logs a `WARN` message and
allows both entries to coexist in the registry until the old socket's
TCP EOF triggers cleanup.

**Using the new routes:**

| Use case | Route |
|----------|-------|
| Target by self-reported name (legacy / human-friendly) | `POST /api/agents/{agent_id}/command` |
| Target a specific connection unambiguously | `POST /api/connections/{connection_id}/command` |

The `connection_id` is visible in `GET /api/agents` and the dashboard's
real-time WebSocket feed.  Tests in
[tests/identity.rs](../orchestra-server/tests/identity.rs) verify the
behaviour end-to-end.

## Operator identity in audit logs

Every command dispatched by the REST API now includes the authenticated
operator identity in the `Message::TaskRequest` wire message:

```json
{
  "TaskRequest": {
    "task_id": "...",
    "command": "Ping",
    "operator_id": "admin"
  }
}
```

The agent uses `operator_id` when writing its own `AuditEvent` records
so that audit trail entries show who issued the command, rather than
always attributing actions to `"admin"`.  Older agents that do not
recognise the field will still receive commands normally (`operator_id`
has `#[serde(default)]` and is silently ignored during deserialisation
if absent).

## Forward secrecy (optional)

Enable the `forward-secrecy` feature on both `common` and `agent` to add
an ephemeral X25519 key exchange before any `Message` is transmitted:

```toml
# profiles/<name>.toml
features = ["forward-secrecy"]
```

The handshake is a single round-trip:

1. Client and server each generate a fresh `EphemeralSecret` (X25519).
2. They exchange their public keys over the plaintext TCP stream.
3. Both sides compute the same `X25519(priv, peer_pub)` shared secret.
4. HKDF-SHA256 mixes the shared secret with `SHA-256(PSK)` and the
   domain string `"orchestra-fs-v1"` to derive a 32-byte `session_key`.
5. A fresh `CryptoSession` is constructed from `session_key`; all
   subsequent frames are encrypted with that session.

**Forward secrecy guarantee:** a passive observer who later learns the
PSK cannot decrypt recorded sessions because the ephemeral key material
is never persisted.  The PSK remains necessary for authentication
(binding the derived key to the shared secret).

See `common/src/crypto.rs` for the implementation and its unit tests.

## Hardening

1. **Replace the bearer token with mTLS for operators**, or place the
   server behind an SSO-aware reverse proxy and require
   `X-Forwarded-User` to be present (configurable extension point in
   `auth.rs`).
2. **Pin or replace test certificates.** The setup and server-side build
   paths can bake `server_cert_fingerprint` into outbound agents. Use a
   production certificate and rotate pinned fingerprints deliberately.
3. **Pin the dashboard's CSP** if you customise `static/index.html`. The
   shipped page loads no third-party scripts.
4. **Forward the audit log** to your SIEM. The JSONL format is one event
   per line; tail and ship.

## Roadmap

Aligned with [`ROADMAP.md`](../ROADMAP.md):

- ~~HMAC-signed audit events (tamper-evident).~~ **Completed** — each JSONL entry is HMAC-SHA256 signed.
- OIDC / SSO for operator login.
- Per-operator RBAC tied to the cert CN once mTLS is the default
  operator path.
- ~~WebSocket-streamed shell sessions backed by `Command::ShellInput` / `ShellOutput`.~~ **Completed** — REST shell API and PTY sessions are live.
