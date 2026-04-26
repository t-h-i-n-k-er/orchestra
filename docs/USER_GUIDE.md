# Orchestra User Guide

> A practical manual for IT administrators deploying and operating the
> **Orchestra** remote management framework on systems they own or manage.

---

## 1. Introduction

Orchestra is a lightweight, cross-platform remote-management framework for
authorized administration. It supports fleet inventory, approved maintenance
commands, diagnostic collection, signed module deployment, and audited
operator actions through the Orchestra Control Center.

Orchestra is not an exploitation tool. Use it only on systems you own or have
written authorization to manage.

---

## 2. Installation

Requirements: Rust **1.76+**, `pkg-config`, a C compiler, and platform
development packages for any optional features you enable.

```bash
git clone https://github.com/example/orchestra
cd orchestra
cargo build --release --workspace
```

Important binaries:

| Binary | Purpose |
|--------|---------|
| `orchestra-server` | HTTPS dashboard and agent listener. |
| `agent-standalone` | Endpoint agent that dials the server when built with `outbound-c`. |
| `orchestra-builder` | Profile-driven builder for encrypted payloads. |
| `console` | Legacy protocol-test CLI for custom listeners; stock agents use the Control Center. |

---

## 3. TLS and certificate pinning

For production use, supply real TLS material to the Control Center and bake
the server certificate fingerprint into outbound agents.

```bash
# Private CA
openssl req -x509 -newkey ed25519 -keyout ca.key -out ca.pem -days 365 \
    -nodes -subj "/CN=OrchestraCA"

# Server cert
openssl req -newkey ed25519 -keyout server.key -out server.csr -nodes \
    -subj "/CN=orchestra.example.com"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out server.pem -days 365

# SHA-256 fingerprint to set as server_cert_fingerprint
openssl x509 -in server.pem -outform DER | sha256sum | awk '{print $1}'
```

Set `tls_cert_path` and `tls_key_path` in `orchestra-server.toml`.

---

## 4. Deploying the agent

The supported packaged deployment path is an outbound agent built with
`features = ["outbound-c"]`. The agent dials the Control Center's
`agent_addr`, authenticates with `agent_shared_secret`, and pins the server
certificate when `server_cert_fingerprint` is present.

Use the setup wizard for an end-to-end local deployment:

```bash
./scripts/setup.sh
```

Or write a profile by hand:

```toml
target_os         = "linux"
target_arch       = "x86_64"
c2_address        = "10.0.0.5:8444"
encryption_key    = "<base64-32-bytes>"
c_server_secret   = "<same as agent_shared_secret>"
server_cert_fingerprint = "<sha256-der-fingerprint>"
features          = ["outbound-c"]
package           = "agent"
bin_name          = "agent-standalone"
```

Then build:

```bash
cargo run --release -p builder -- build my_agent
```

The Builder writes `dist/<profile>.enc` unless `output_name` overrides the
filename.

---

## 5. Basic operations

Open the dashboard at `https://<server>:<http_port>/`, authenticate with
`admin_token`, then select a connected agent and submit an approved command.
The stock `agent-standalone` binary does not listen for direct console
connections.

Common command families:

| Command family | Purpose |
|----------------|---------|
| `Ping`, `GetSystemInfo` | Liveness and inventory. |
| File operations | Read/write within configured `allowed_paths`. |
| Approved scripts | Run administrator-approved maintenance tasks. |
| Module deployment | Fetch, verify, and load signed capability modules. |
| Optional features | Persistence, network discovery, remote assistance, and HCI research only when compiled in and authorized. |

---

## 6. Advanced features

### 6.1 Plugin deployment

Plugins are signed shared libraries decrypted and loaded in process memory.
See `docs/DESIGN.md` for the module-loader design.

### 6.2 Persistence (opt-in)

Enable with `persistence_enabled = true` in `agent.toml`. The agent installs
a per-user systemd unit, launchd entry, or scheduled task depending on the
platform. Disable by setting the flag to `false` and reloading config.

### 6.3 Remote assistance (opt-in, consent-gated)

Compile the agent with `--features remote-assist`. Input simulation is
permitted only while the platform consent marker is present.

### 6.4 Network discovery (opt-in)

Compile with `--features network-discovery`. The agent reports local network
inventory for authorized troubleshooting and asset management.

### 6.5 Forward secrecy (opt-in)

Compile both agent and server with `--features forward-secrecy` to add an
ephemeral X25519 key exchange before application messages.

---

## 7. Key management

Profiles store an AES-256 key for payload encryption. The Builder accepts a
base64 key or `file:/path/to/key.bin` and warns about obvious placeholders.

```bash
cargo run --release -p builder -- configure --name my-profile
cargo run --release -p builder -- build my-profile
```

Keep `c_server_secret`, `admin_token`, and payload encryption keys out of
source control.

---

## 8. Audit logging and monitoring

Every command produces an `AuditEvent` appended to the Control Center audit
log. The `user` field contains the authenticated Control Center operator.

Sample entry:

```json
{"timestamp":1740000000,"agent_id":"web-01","user":"alice@example.com",
 "action":"ReadFile(/var/log/syslog)","details":"OK (4096 bytes)",
 "outcome":"Success"}
```

Forward the JSONL audit log to your SIEM.

---

## 9. Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `connection refused` | Control Center agent port unreachable, firewall, or wrong port. |
| `AES-GCM authentication failed` | Pre-shared key mismatch. |
| `tls handshake failure` | Server certificate pin mismatch or TLS material problem. |
| `Path is not under any allowed root` | Add the directory to `allowed_paths` in `agent.toml`. |
| Plugin load fails with `ELF magic` | Plugin built for the wrong target triple. |

For deeper diagnostics, run agent and server with
`RUST_LOG=debug,orchestra=trace` and inspect the server audit log.

---

## 10. Environment validation

The `env-validation` Cargo feature collects startup environment signals and,
when explicitly configured, can refuse startup on selected policy violations.
Defaults are low-false-positive: VM, tracer-process, debugger, timing, and
sandbox signals are informational unless a matching config knob is enabled.

```toml
# Only start normally if the machine's DNS/AD domain matches this string.
# Leave unset to skip the domain check.
required_domain = "corp.example.com"

# Refuse startup when a hypervisor is detected. Defaults to false because many
# legitimate enterprise endpoints are virtualized.
refuse_in_vm = false

# Refuse only when a debugger is attached to the agent process itself.
# Unrelated same-user processes named gdb/strace remain informational.
refuse_when_debugged = false

# Optional combined sandbox score threshold. Leave unset to make the score
# telemetry-only.
sandbox_score_threshold = 80
```

| Signal | Enforcement behavior |
|--------|----------------------|
| Domain mismatch | Refuses only when `required_domain` is set and does not match. |
| Debugger attached | Refuses only when `refuse_when_debugged = true`. |
| VM/cloud indicators | Refuses only when `refuse_in_vm = true`. |
| Sandbox score | Refuses only when `sandbox_score_threshold` is set and met. |
| Tracer process names | Informational; unrelated same-user `gdb`/`strace` processes do not refuse startup. |

If a configured refusal policy fails, the agent logs an error and enters a
dormant sleep loop rather than continuing management actions.

---

## 11. Transport compatibility

The supported agent transport is the outbound Control Center channel:
`agent-standalone` connects to `orchestra-server`, validates TLS with
certificate pinning when configured, then uses the authenticated message
protocol. The `traffic-normalization` feature remains an experimental library
compatibility flag and is not a documented deployment mode for stock agents.

---

## 12. Reporting security issues

Please email `security@example.com` with reproduction steps. Do **not** file
public issues for unfixed vulnerabilities.