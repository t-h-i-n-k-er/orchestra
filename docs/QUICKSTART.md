# Quick Start Guide

This guide walks you from a fresh `git clone` to issuing your first command on
a managed endpoint in eight steps. It covers both Linux/macOS and Windows.

---

## Table of contents

1. [Prerequisites](#1-prerequisites)
2. [Clone the repository](#2-clone-the-repository)
3. [Run the quickstart script](#3-run-the-quickstart-script)
4. [Open the dashboard](#4-open-the-dashboard)
5. [Review the generated profile](#5-review-the-generated-profile)
6. [Deploy the agent](#6-deploy-the-agent)
7. [Verify connectivity](#7-verify-connectivity)
8. [Issue your first command](#8-issue-your-first-command)

---

## 1. Prerequisites

Install the following before starting:

| Tool | How to install |
|---|---|
| **Git** | System package manager |
| **Rust** (stable) | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` (Unix) or [rustup.rs](https://rustup.rs) (Windows) |
| **C compiler** | `gcc`/`clang` (Unix), Visual Studio Build Tools (Windows) |
| **OpenSSL** | `apt install libssl-dev` / `brew install openssl` / Windows installer |
| **pkg-config** | `apt install pkg-config` / `brew install pkg-config` |

> **Tip:** The quickstart script checks for Rust and offers to install it. It
> also verifies the build toolchain, so you can just run it and follow any
> prompts.

### Verify

```sh
cargo --version        # should print e.g. cargo 1.82.0
rustc --version        # should print e.g. rustc 1.82.0
git --version          # should print a recent version
```

Or use the bundled verification script:

```sh
./scripts/verify-setup.sh
```

This checks all required and optional dependencies and prints a pass/fail
report.

---

## 2. Clone the repository

```sh
git clone https://github.com/t-h-i-n-k-er/orchestra.git
cd orchestra
```

---

## 3. Run the quickstart script

### Linux / macOS

```sh
./scripts/quickstart.sh
```

### Windows

```bat
scripts\quickstart.bat
```

### What the script does

The quickstart script automates the entire setup:

1. **Checks for Rust** — offers to install via `rustup` if missing.
2. **Builds `orchestra-builder`** in release mode.
3. **Detects your platform** — OS, architecture, and LAN IP.
4. **Generates random credentials** — AES-256 encryption key, agent PSK, admin bearer token.
5. **Creates a self-signed TLS certificate** — covers `127.0.0.1`, your LAN IP, and `localhost`.
6. **Writes a default outbound profile** — `profiles/default.toml` with `outbound-c` enabled.
7. **Builds the agent payload** — encrypted binary in `dist/default.enc`.
8. **Writes `orchestra-server.toml`** — server config with matching credentials.
9. **Builds the Control Center** — `orchestra-server` in release mode.
10. **Prints credentials and URLs** — dashboard URL, bearer token, payload path.

When the script asks **"Start the Orchestra Control Center now?"**, say **y**.

### Customisation

| Variable | Default | Purpose |
|---|---|---|
| `ORCHESTRA_PROFILE` | `default` | Profile name |
| `ORCHESTRA_HTTP_PORT` | `8443` | Dashboard HTTPS port |
| `ORCHESTRA_AGENT_PORT` | `8444` | Agent listener port |
| `ORCHESTRA_SKIP_SERVER` | `0` | Set to `1` to skip auto-start |

```sh
ORCHESTRA_HTTP_PORT=9443 ORCHESTRA_AGENT_PORT=9444 ./scripts/quickstart.sh
```

---

## 4. Open the dashboard

1. Open a browser and navigate to the URL printed by the quickstart:

   ```
   https://<your-ip>:8443/
   ```

2. Your browser will warn about the self-signed certificate. Click **Advanced** → **Proceed** (this is safe on a local network; use a real certificate in production).

3. The dashboard prompts for a bearer token. Paste the **Admin bearer token** from the quickstart output.

4. You should see an empty **Agents** table — no endpoints are connected yet.

### Dashboard overview

| Section | Purpose |
|---|---|
| **Agents** | Lists connected endpoints with hostname, agent ID, last-seen timestamp, and peer address. |
| **Send command** | Select an agent and dispatch a command (Ping, GetSystemInfo, file ops, shell). |
| **Audit log** | Live-updated log of all operator actions. |

---

## 5. Review the generated profile

The quickstart creates `profiles/default.toml`. Open it to see the configuration:

```toml
target_os               = "linux"
target_arch             = "x86_64"
c2_address              = "192.168.1.100:8444"
encryption_key          = "<random-base64>"
c_server_secret         = "<random-base64>"
server_cert_fingerprint = "<sha256-hex>"
features                = ["outbound-c"]
package                 = "agent"
bin_name                = "agent-standalone"
```

Key fields:

| Field | Meaning |
|---|---|
| `c2_address` | The `host:port` the agent dials. Must match `agent_addr` in `orchestra-server.toml`. |
| `encryption_key` | AES-256 key used to encrypt the payload at rest. |
| `c_server_secret` | Pre-shared key the agent uses to authenticate to the server. |
| `server_cert_fingerprint` | SHA-256 DER fingerprint the agent pins against. |
| `features` | Cargo features compiled into the agent binary. |
| `package` | Must be `"agent"` (never `"launcher"`). |
| `bin_name` | `"agent-standalone"` for outbound deployments. |

To create a profile for a different target OS:

```sh
# Edit profiles/default.toml and change target_os / target_arch,
# or create a new profile:
./scripts/setup.sh    # interactive wizard
```

---

## 6. Deploy the agent

The quickstart produced an encrypted agent binary at `dist/default.enc`. This
section covers two deployment methods.

### Option A: Direct deployment (recommended for testing)

For the `outbound-c` deployment style, the agent is a self-contained binary
that dials the Control Center. The Builder encrypts the binary for secure
transport, but you can also extract the raw binary:

```sh
# If you have the profile's encryption key, you can decrypt:
# cargo run --release -p payload-packager -- \
#     --input dist/default.enc --output dist/agent-standalone --key <key> --decrypt

# For quick local testing, build directly:
cargo build --release -p agent --features outbound-c \
    --bin agent-standalone
```

Copy the resulting binary to your target endpoint and run:

```sh
./agent-standalone
```

The agent dials the Control Center at the address baked into the binary during
build. No command-line flags are needed for release builds.

> **Debug builds** can override the baked address with environment variables:
> ```sh
> ORCHESTRA_C=10.0.0.5:8444 ORCHESTRA_SECRET=mysecret ./agent-standalone
> ```

### Option B: Launcher + payload (for in-memory delivery)

The launcher is a small stub that fetches and decrypts an encrypted payload
over HTTP at runtime. This is useful when you want to serve the agent from a
central location.

```sh
# 1. Start the dev-server to serve the encrypted payload:
cargo run --release -p dev-server -- --port 8000

# 2. Build the launcher for the target platform:
cargo build --release -p launcher

# 3. Copy the launcher to the endpoint and run:
./launcher --url http://<this-host>:8000/default.enc --key '<encryption-key>'
```

> **Important:** The launcher stub is deployed *directly* to the endpoint. The
> encrypted agent payload is what gets served over HTTP. Never use
> `package = "launcher"` in a profile — the Builder will reject it.

---

## 7. Verify connectivity

After starting the agent on the target endpoint:

1. Return to the dashboard at `https://<your-ip>:8443/`.
2. The agent should appear in the **Agents** table within a few seconds.
3. You'll see:
   - **agent_id** — the endpoint's hostname.
   - **connection_id** — server-assigned unique connection identifier.
   - **last_seen** — timestamp of the last heartbeat.
   - **peer** — IP address of the agent.

If the agent doesn't appear:

| Symptom | Check |
|---|---|
| Agent exits immediately | Check that the Control Center is running on `c2_address`. |
| `connection refused` | Firewall blocking the agent port (default 8444). Verify `agent_addr` in server config. |
| `AES-GCM authentication failed` | PSK mismatch between profile's `c_server_secret` and server's `agent_shared_secret`. |
| `tls handshake failure` | Certificate fingerprint mismatch. Regenerate or update `server_cert_fingerprint`. |

For deeper diagnostics, run with verbose logging:

```sh
RUST_LOG=debug,orchestra=trace ./agent-standalone
```

---

## 8. Issue your first command

From the dashboard:

1. Select your agent from the **Agents** table.
2. Click **Send command**.
3. Choose a command and submit:

### Ping

```json
{ "command": "Ping" }
```

Expected response: the agent replies with a pong and the round-trip time.

### Get system info

```json
{ "command": "GetSystemInfo" }
```

Returns OS, architecture, uptime, memory info, and hostname.

### List directory

```json
{ "command": { "ListDirectory": { "path": "/var/log" } } }
```

Lists files within the configured `allowed_paths` directories.

### Start an interactive shell

```json
{ "command": "StartShell" }
```

Opens a PTY session on the agent. Use `ShellInput` / `ShellOutput` to
send and receive data.

### Using the REST API directly

You can also send commands via `curl`:

```sh
# List connected agents
curl -sk -H "Authorization: Bearer <admin_token>" \
    https://127.0.0.1:8443/api/agents

# Send a Ping
curl -sk -X POST \
    -H "Authorization: Bearer <admin_token>" \
    -H "Content-Type: application/json" \
    -d '{"command":"Ping"}' \
    https://127.0.0.1:8443/api/agents/<agent_id>/command

# View the audit log
curl -sk -H "Authorization: Bearer <admin_token>" \
    https://127.0.0.1:8443/api/audit
```

---

## Next steps

- **Enable additional features** — edit the profile and add features like
  `persistence`, `network-discovery`, or `remote-assist`. See
  [FEATURES.md](FEATURES.md) for the complete reference.
- **Configure for production** — replace the self-signed TLS certificate,
  rotate credentials, set up a reverse proxy. See
  [CONTROL_CENTER.md](CONTROL_CENTER.md) for production hardening.
- **Understand the architecture** — see [ARCHITECTURE.md](ARCHITECTURE.md)
  for wire protocol, crypto, and transport details.
- **Review security practices** — see [SECURITY.md](SECURITY.md) for the
  threat model and hardening checklist.
- **Set up TLS certificates** — use `./scripts/generate-certs.sh` or supply
  your own certificates.

## Interactive wizard

For more control over every parameter, use the interactive setup wizard:

```sh
./scripts/setup.sh          # Linux / macOS
```

The wizard prompts for:

1. Profile name
2. Target OS and architecture
3. Deployment style (outbound vs launcher)
4. Control Center address
5. Optional Cargo features
6. Credential generation
7. TLS certificate generation
8. Cross-compilation toolchain setup
9. Payload build
10. Server start

Windows users can use the PowerShell equivalent:

```powershell
.\scripts\setup.ps1
```

## Cross-compilation

To build for a platform different from your host:

```sh
# Install the target
rustup target add x86_64-pc-windows-gnu

# Build the agent for Windows from Linux
cargo build --release -p agent --target x86_64-pc-windows-gnu \
    --features outbound-c --bin agent-standalone

# Or use the Builder with a profile
# (edit profiles/my_agent.toml to set target_os = "windows")
./target/release/orchestra-builder build my_agent
```

For Windows cross-compilation from Linux without `mingw-w64`, the setup wizard
automatically falls back to `cargo-zigbuild`. See [ARCHITECTURE.md](ARCHITECTURE.md)
for transport-level details.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `cargo` not found | Rust not installed | Run `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Build fails with linker error | Missing C toolchain for target | Install `mingw-w64` (Windows) or Xcode CLI Tools (macOS) |
| Agent exits with `connection refused` | Server not running or wrong port | Start the Control Center; verify `agent_addr` matches profile's `c2_address` |
| `AES-GCM authentication failed` | PSK mismatch | Regenerate profile and server config together with `quickstart.sh` |
| TLS handshake failure | Certificate mismatch | Regenerate certs with `./scripts/generate-certs.sh` and update fingerprint |
| Agent not visible in dashboard | Agent not connected | Check agent logs with `RUST_LOG=debug`; verify network connectivity |
| `Path is not under any allowed root` | File operation outside `allowed_paths` | Add the directory to `allowed_paths` in `agent.toml` |
| Plugin load fails with `ELF magic` | Wrong target architecture | Rebuild the plugin for the agent's target triple |

For verbose logging on either side:

```sh
# Agent
RUST_LOG=debug,orchestra=trace ./agent-standalone

# Server
RUST_LOG=debug,orchestra=trace ./target/release/orchestra-server --config orchestra-server.toml
```
