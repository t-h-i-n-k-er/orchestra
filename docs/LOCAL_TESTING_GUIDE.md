# Local C2 Testing Guide — Server + Agent on the Same Linux Machine

This guide walks you through deploying the Orchestra C2 server and agent on a
**single Linux machine** for local end-to-end testing. It covers:

1. Prerequisites
2. Building binaries
3. Starting the server
4. Building & deploying the agent
5. Sending commands (Ping, GetSystemInfo, ListDirectory, ReadFile, StartShell, etc.)
6. Testing screen capture (CaptureScreen)
7. Troubleshooting

---

## 1. Prerequisites

| Requirement | Install |
|---|---|
| Rust toolchain (nightly or stable) | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| `openssl` | `sudo apt install openssl` |
| `pkg-config` / `libssl-dev` | `sudo apt install pkg-config libssl-dev` |
| X11 dev libraries (for `remote-assist`) | `sudo apt install libx11-dev libxrandr-dev libxext-dev` |
| `libclang` (for `zbus` bindgen, Wayland screenshot) | `sudo apt install libclang-dev` |

> **Tip:** If you only want basic commands (no screenshots), skip the X11/libclang
> packages and omit `--features remote-assist` from the build commands.

---

## 2. Generate TLS Certificates

The server and agent communicate over TLS. A self-signed cert is fine for local
testing. If you already have `secrets/server.crt` and `secrets/server.key`,
skip to step 3.

```bash
cd /path/to/la   # your workspace root

# Generate certs (auto-detects your LAN IP and adds it as a SAN)
./scripts/generate-certs.sh

# Note the SHA-256 fingerprint printed — you'll need it below.
# Example output:
#   Certificate SHA-256 fingerprint: 9cf7a2d57b0b259e1c8e04a4f2c3721248054ea4d7bcf55ddf2247ac98883bd9
```

If you ever regenerate certs, recompute the fingerprint:

```bash
CERT_FP=$(openssl x509 -in secrets/server.crt -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
echo "$CERT_FP"
```

---

## 3. Create the Server Configuration

Create or edit `orchestra-server.toml` in the workspace root:

```toml
# orchestra-server.toml
http_addr            = "0.0.0.0:8443"        # Admin dashboard / REST API
agent_addr           = "0.0.0.0:8444"        # Agent listener
agent_shared_secret  = "RvDPwz+Xl7WuOkRnE3mIJjDy9B9oDyMvUg8fYSZ2EFg="
admin_token          = "0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg"
audit_log_path       = "secrets/orchestra-audit.jsonl"
static_dir           = "orchestra-server/static"
tls_cert_path        = "secrets/server.crt"
tls_key_path         = "secrets/server.key"
command_timeout_secs = 30
```

> **Important:** `agent_shared_secret` must match the secret baked into the
> agent binary at build time (see step 5).

---

## 4. Build the Server

```bash
cargo build --release --bin orchestra-server
```

The binary lands at `target/release/orchestra-server`.

---

## 5. Build the Agent (with outbound-c feature)

The agent needs three **compile-time** environment variables injected via
`option_env!()`:

| Variable | Value |
|---|---|
| `ORCHESTRA_C_ADDR` | `<your-ip>:8444` (the `agent_addr` from the server config) |
| `ORCHESTRA_C_SECRET` | Must match `agent_shared_secret` in the server config |
| `ORCHESTRA_C_CERT_FP` | SHA-256 fingerprint of `secrets/server.crt` |

```bash
# Detect your LAN IP (or use 127.0.0.1 for localhost-only testing)
MY_IP=$(hostname -I | awk '{print $1}')
# For localhost-only testing, use: MY_IP=127.0.0.1

# Get the cert fingerprint
CERT_FP=$(openssl x509 -in secrets/server.crt -outform DER 2>/dev/null | sha256sum | awk '{print $1}')

# Basic agent (no screenshot support)
ORCHESTRA_C_ADDR=${MY_IP}:8444 \
ORCHESTRA_C_SECRET='RvDPwz+Xl7WuOkRnE3mIJjDy9B9oDyMvUg8fYSZ2EFg=' \
ORCHESTRA_C_CERT_FP="$CERT_FP" \
cargo build --release --bin agent-standalone --features outbound-c

# ── OR ── with screen capture / remote-assist support ──
ORCHESTRA_C_ADDR=${MY_IP}:8444 \
ORCHESTRA_C_SECRET='RvDPwz+Xl7WuOkRnE3mIJjDy9B9oDyMvUg8fYSZ2EFg=' \
ORCHESTRA_C_CERT_FP="$CERT_FP" \
cargo build --release --bin agent-standalone --features "outbound-c,remote-assist"
```

The binary lands at `target/release/agent-standalone`.

---

## 6. Start the Server

```bash
# Kill any existing instances
pkill -f orchestra-server 2>/dev/null; sleep 1

# Start the server in the background
RUST_LOG=info ./target/release/orchestra-server --config orchestra-server.toml > /tmp/server.log 2>&1 &

# Wait for startup
sleep 2

# Verify it's listening
ss -tlnp | grep -E '8443|8444'
```

You should see both ports 8443 (dashboard) and 8444 (agent) listening.

### Quick health check

```bash
curl -sk -H 'Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg' \
  'https://127.0.0.1:8443/api/agents'
# Expected: []  (empty list — no agents connected yet)
```

---

## 7. Start the Agent

```bash
# Kill any existing instances
pkill -f agent-standalone 2>/dev/null; sleep 1

# Start the agent in the background
RUST_LOG=info ./target/release/agent-standalone > /tmp/agent.log 2>&1 &

# Wait for registration
sleep 3

# Verify the agent registered
curl -sk -H 'Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg' \
  'https://127.0.0.1:8443/api/agents' | python3 -m json.tool
```

You should see a JSON array with one agent entry containing an `agent_id` like
`Nier-0882b706-1615-421c-91df-c7c1a29eda41`.

---

## 8. Send Commands — The Basics

All commands are sent via `POST /api/agents/<agent_id>/command` with JSON body
`{"command": <Command>}`. Simple commands (no fields) use a string; commands
with fields use a nested object.

### Helper: capture the agent ID

```bash
export AID=$(curl -sk -H 'Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg' \
  'https://127.0.0.1:8443/api/agents' | \
  python3 -c "import json,sys; print(max(json.load(sys.stdin), key=lambda a: a['last_seen'])['agent_id'])")
echo "Agent ID: $AID"
```

### 8.1 Ping

```bash
curl -sk --max-time 10 -X POST \
  -H 'Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg' \
  -H 'Content-Type: application/json' \
  -d '{"command":"Ping"}' \
  "https://127.0.0.1:8443/api/agents/$AID/command"
# Expected: {"task_id":"...","outcome":"ok","output":"pong","error":null}
```

### 8.2 GetSystemInfo

```bash
curl -sk --max-time 10 -X POST \
  -H 'Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg' \
  -H 'Content-Type: application/json' \
  -d '{"command":"GetSystemInfo"}' \
  "https://127.0.0.1:8443/api/agents/$AID/command"
# Expected: {"task_id":"...","outcome":"ok","output":"{\"cpu_count\":..., \"hostname\":\"...\", ...}","error":null}
```

### 8.3 ListDirectory

```bash
curl -sk --max-time 10 -X POST \
  -H 'Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg' \
  -H 'Content-Type: application/json' \
  -d '{"command":{"ListDirectory":{"path":"/tmp"}}}' \
  "https://127.0.0.1:8443/api/agents/$AID/command"
# Expected: {"task_id":"...","outcome":"ok","output":"[{\"name\":\"...\",\"is_dir\":false,\"size\":123}, ...]","error":null}
```

### 8.4 ReadFile

```bash
# First create a test file
echo "hello from orchestra" > /tmp/test_read.txt

curl -sk --max-time 10 -X POST \
  -H 'Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg' \
  -H 'Content-Type: application/json' \
  -d '{"command":{"ReadFile":{"path":"/tmp/test_read.txt"}}}' \
  "https://127.0.0.1:8443/api/agents/$AID/command"
# Expected: {"task_id":"...","outcome":"ok","output":"aGVsbG8gZnJvbSBvcmNoZXN0cmEK","error":null}
# The output is base64-encoded. Decode:
# echo "aGVsbG8gZnJvbSBvcmNoZXN0cmEK" | base64 -d  →  "hello from orchestra"
```

### 8.5 WriteFile

```bash
# Write "test content" (base64: dGVzdCBjb250ZW50) to /tmp/orchestra_write_test.txt
curl -sk --max-time 10 -X POST \
  -H 'Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg' \
  -H 'Content-Type: application/json' \
  -d '{"command":{"WriteFile":{"path":"/tmp/orchestra_write_test.txt","content":"dGVzdCBjb250ZW50"}}}' \
  "https://127.0.0.1:8443/api/agents/$AID/command"

# Verify:
cat /tmp/orchestra_write_test.txt
# Expected: test content
```

### 8.6 StartShell / ShellInput / ShellOutput / CloseShell

```bash
# Open an interactive shell session
SHELL_RESP=$(curl -sk --max-time 10 -X POST \
  -H 'Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg' \
  -H 'Content-Type: application/json' \
  -d '{"command":"StartShell"}' \
  "https://127.0.0.1:8443/api/agents/$AID/command")
echo "$SHELL_RESP"
# Expected: {"task_id":"...","outcome":"ok","output":"{\"session_id\":\"...\"}","error":null}

# Extract the session ID
SID=$(echo "$SHELL_RESP" | python3 -c "import json,sys; print(json.loads(json.load(sys.stdin)['output'])['session_id'])")
echo "Shell session: $SID"

# Send a command (base64-encoded "id")
curl -sk --max-time 10 -X POST \
  -H 'Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg' \
  -H 'Content-Type: application/json' \
  -d "{\"command\":{\"ShellInput\":{\"session_id\":\"$SID\",\"data\":\"$(echo -n 'id' | base64)\"}}}" \
  "https://127.0.0.1:8443/api/agents/$AID/command"

# Read shell output
sleep 1
curl -sk --max-time 10 -X POST \
  -H 'Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg' \
  -H 'Content-Type: application/json' \
  -d "{\"command\":{\"ShellOutput\":{\"session_id\":\"$SID\"}}}" \
  "https://127.0.0.1:8443/api/agents/$AID/command"
# Output is base64-encoded stdout+stderr

# Close the shell
curl -sk --max-time 10 -X POST \
  -H 'Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg' \
  -H 'Content-Type: application/json' \
  -d "{\"command\":{\"CloseShell\":{\"session_id\":\"$SID\"}}}" \
  "https://127.0.0.1:8443/api/agents/$AID/command"
```

### 8.7 ListProcesses

```bash
curl -sk --max-time 10 -X POST \
  -H 'Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg' \
  -H 'Content-Type: application/json' \
  -d '{"command":"ListProcesses"}' \
  "https://127.0.0.1:8443/api/agents/$AID/command"
# Expected: JSON array of running processes
```

### 8.8 DiscoverNetwork

> Requires `--features network-discovery` at build time.

```bash
curl -sk --max-time 15 -X POST \
  -H 'Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg' \
  -H 'Content-Type: application/json' \
  -d '{"command":"DiscoverNetwork"}' \
  "https://127.0.0.1:8443/api/agents/$AID/command"
# Expected: JSON with arp_hosts, interfaces, open_ports, etc.
```

---

## 9. Testing Screen Capture (CaptureScreen)

### 9.1 Build with remote-assist

The `CaptureScreen` command requires the `remote-assist` feature flag. If you
didn't build with it, rebuild:

```bash
MY_IP=$(hostname -I | awk '{print $1}')
CERT_FP=$(openssl x509 -in secrets/server.crt -outform DER 2>/dev/null | sha256sum | awk '{print $1}')

ORCHESTRA_C_ADDR=${MY_IP}:8444 \
ORCHESTRA_C_SECRET='RvDPwz+Xl7WuOkRnE3mIJjDy9B9oDyMvUg8fYSZ2EFg=' \
ORCHESTRA_C_CERT_FP="$CERT_FP" \
cargo build --release --bin agent-standalone --features "outbound-c,remote-assist"
```

### 9.2 Create the consent flag

Screen capture requires an explicit consent file on the target machine
(this is YOUR machine in local testing):

```bash
touch ~/.orchestra-consent
```

### 9.3 Linux capture backends

The agent tries backends in this order:

1. **Wayland** (if `$WAYLAND_DISPLAY` is set) → XDG Desktop Portal via D-Bus
2. **X11** (if `$DISPLAY` is set) → `x11cap` crate captures the root window
3. **Framebuffer** (`/dev/fb0`) → raw framebuffer read (headless / VT)

For a standard Ubuntu desktop with X11, the X11 path will be used automatically.

### 9.4 Send the CaptureScreen command

```bash
# Restart the agent if you rebuilt it
pkill -f agent-standalone; sleep 1
RUST_LOG=info ./target/release/agent-standalone > /tmp/agent.log 2>&1 &
sleep 3

# Re-capture the agent ID
export AID=$(curl -sk -H 'Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg' \
  'https://127.0.0.1:8443/api/agents' | \
  python3 -c "import json,sys; print(max(json.load(sys.stdin), key=lambda a: a['last_seen'])['agent_id'])")

# Take a screenshot
curl -sk --max-time 15 -X POST \
  -H 'Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg' \
  -H 'Content-Type: application/json' \
  -d '{"command":"CaptureScreen"}' \
  "https://127.0.0.1:8443/api/agents/$AID/command" > /tmp/screenshot_resp.json

# Extract and decode the base64 PNG
python3 -c "
import json, base64
resp = json.load(open('/tmp/screenshot_resp.json'))
if resp['outcome'] == 'ok':
    png = base64.b64decode(resp['output'])
    with open('/tmp/screenshot.png', 'wb') as f:
        f.write(png)
    print(f'Screenshot saved: /tmp/screenshot.png ({len(png)} bytes)')
else:
    print(f'Error: {resp[\"error\"]}')
"

# View the screenshot
xdg-open /tmp/screenshot.png
```

### 9.5 Troubleshooting screenshots

| Error | Cause | Fix |
|---|---|---|
| `"remote-assist feature not enabled"` | Agent built without `--features remote-assist` | Rebuild with the feature |
| `"Remote assistance consent not granted"` | Missing `~/.orchestra-consent` | `touch ~/.orchestra-consent` |
| `"failed to open X11 display"` | No `$DISPLAY` set (headless) | Run under an X session, or test fb0/Wayland |
| `"X11 capture_frame failed"` | X11 permissions | Ensure your user has X access (`xhost +local:`) |
| Portal timeout | Wayland + no portal service | Install `xdg-desktop-portal`, or unset `WAYLAND_DISPLAY` to fallback |

---

## 10. Clean Up

```bash
# Stop the agent and server
pkill -f agent-standalone
pkill -f orchestra-server

# Remove consent file (optional)
rm -f ~/.orchestra-consent

# Clean up temp logs
rm -f /tmp/server.log /tmp/agent.log /tmp/screenshot_resp.json
```

---

## Quick Reference — Command JSON Format

| Command | JSON Body |
|---|---|
| `Ping` | `{"command":"Ping"}` |
| `GetSystemInfo` | `{"command":"GetSystemInfo"}` |
| `ListDirectory` | `{"command":{"ListDirectory":{"path":"/tmp"}}}` |
| `ReadFile` | `{"command":{"ReadFile":{"path":"/etc/hostname"}}}` |
| `WriteFile` | `{"command":{"WriteFile":{"path":"/tmp/f.txt","content":"BASE64"}}}` |
| `StartShell` | `{"command":"StartShell"}` |
| `ShellInput` | `{"command":{"ShellInput":{"session_id":"...","data":"BASE64"}}}` |
| `ShellOutput` | `{"command":{"ShellOutput":{"session_id":"..."}}}` |
| `CloseShell` | `{"command":{"CloseShell":{"session_id":"..."}}}` |
| `CaptureScreen` | `{"command":"CaptureScreen"}` |
| `ListProcesses` | `{"command":"ListProcesses"}` |
| `DiscoverNetwork` | `{"command":"DiscoverNetwork"}` |
| `Shutdown` | `{"command":"Shutdown"}` |

> **Note:** Binary data fields (`content`, `data`) and binary outputs
> (`ReadFile`, `ShellOutput`, `CaptureScreen`) are base64-encoded.
