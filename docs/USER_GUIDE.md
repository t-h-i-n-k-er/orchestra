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

### 6.6 Hollowing module (Windows, advanced)

The `hollowing` crate provides Windows process hollowing for in-memory payload
execution.

- Current state: PE64 is the primary supported path; PE32/WOW64 support exists
  but should be treated as an evolving compatibility path.
- Workflow: create suspended target process, unmap image, map payload image,
  apply relocations/import fixups, set thread context to payload entry, resume.
- Limitation: remote manual-map/import repair may depend on ASLR layout
  assumptions for shared system DLL mappings; this can break in hardened or
  unusual session layouts where local and remote module bases diverge.

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

| Symptom | Likely cause | Suggested fix |
|---------|--------------|---------------|
| `connection refused` | Control Center agent port unreachable, firewall, or wrong port. | Verify `agent_addr`/port, routing, and host firewall policy. |
| `AES-GCM authentication failed` | Pre-shared key mismatch. | Rotate and re-deploy matching shared secrets/profile values. |
| `tls handshake failure` | Server certificate pin mismatch or TLS material problem. | Recalculate `server_cert_fingerprint` and verify cert/key pair paths. |
| `Path is not under any allowed root` | Requested path is outside configured allow-list. | Add the required directory to `allowed_paths` in `agent.toml`. |
| Plugin load fails with `ELF magic` | Plugin built for the wrong target triple. | Rebuild module for the agent target architecture/OS. |
| Agent enters dormant state on cloud VM | IMDS unreachable, or `cloud_instance_id` not configured for VM-refusal bypass. | Ensure `169.254.169.254` is reachable, set `cloud_instance_id`, or enable `cloud_instance_allow_without_imds`. |
| VM detected on legitimate cloud instance | Niche cloud provider hypervisor name is not in expected list. | Add provider-specific names to `vm_detection_extra_hypervisor_names` in `agent.toml`. |
| Sandbox score unexpectedly high on Linux | Desktop-window fallback `/proc/*/environ` scan visibility is limited by process permissions. | Run with required capabilities/permissions, or treat the desktop-window indicator as non-enforcing telemetry. |

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

### Cloud instance whitelisting

When `refuse_in_vm = true`, use cloud allowlisting to prevent known-good cloud
instances from being treated as hostile VMs.

Provider examples:

```toml
[malleable_profile]
# Primary exact-match allowlist entry
cloud_instance_id = "i-0123456789abcdef0"          # AWS EC2 example
# cloud_instance_id = "2f1b4f3d-8d11-4c18-9d1f-..." # Azure VM id example
# cloud_instance_id = "1234567890123456789"         # GCP numeric instance-id example

# Optional fallback knobs when metadata identity is partially unavailable
cloud_instance_allow_without_imds = false
cloud_instance_fallback_ids = [
   "i-012345*",          # AWS-style prefix pattern
   "2f1b4f3d-*",         # Azure UUID-style prefix pattern
   "1234567890*"         # GCP numeric prefix pattern
]
```

IMDS reachability requirement:

- The agent must be able to reach `169.254.169.254` during startup checks;
   connectivity probes are tuned for a 200 ms connect timeout with bounded
   retry behavior.

Common causes of IMDS unreachability:

- Host firewall rules blocking link-local metadata access.
- Transparent HTTP proxy policy intercepting or denying metadata traffic.
- Seccomp profiles that block `connect`/socket syscalls for the agent process.

Fallback behavior summary:

- `cloud_instance_allow_without_imds = true`: bypass can proceed when IMDS is
  reachable but instance-id body parsing is unavailable.
- `cloud_instance_fallback_ids`: allows operator-defined fallback identifiers
  when metadata identity fetch is restricted in the deployment environment.

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

---

## 13. Network Compatibility Layer

Some corporate networks deploy **deep packet inspection (DPI)** middleboxes
that flag, throttle, or drop opaque encrypted traffic. Orchestra ships with
an optional traffic normalization layer that frames its already‑encrypted
wire bytes as TLS 1.2 application‑data records, so such middleboxes will
classify the flow as ordinary TLS.

The layer lives in [`common::normalized_transport`](../common/src/normalized_transport.rs)
and is selected per agent via the `traffic_profile` field in `agent.toml`:

```toml
# ~/.config/orchestra/agent.toml

# "raw" (default) — length‑prefixed AES‑GCM ciphertext.
# "tls"           — wrap each record as a TLS 1.2 application_data record
#                   (0x17 0x03 0x03 <len>) and perform a fake
#                   ClientHello/ServerHello handshake at connect time.
traffic_profile = "tls"
```

### What gets sent on the wire

With `traffic_profile = "tls"` the agent and controller exchange:

1. A `ClientHello` (record type `0x16`, version `0x0303`, handshake type `0x01`)
   carrying a 32‑byte random, a random session id, the cipher suites
   `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
   `TLS_CHACHA20_POLY1305_SHA256`, and a random extensions blob.
2. A symmetric `ServerHello` (handshake type `0x02`).
3. Subsequent application messages, each as one TLS 1.2 application‑data
   record: `0x17 0x03 0x03 <u16 length> <u16 pad_len> <pad> <ciphertext>`.

The pad length is uniformly random in `[0, 64]` bytes per record so the
record‑size distribution matches real TLS sessions rather than the
fixed‑shape distribution of the underlying serialized messages.

> **Security note.** The normalization layer is for traffic *classification*,
> not confidentiality. Message confidentiality and integrity are still
> provided by the inner AES‑GCM session (`CryptoSession`). The fake
> handshake is intentionally not validated by the peer beyond its wire
> structure — both sides know they are not actually negotiating TLS.

### Self‑verification with `tcpdump` / Wireshark

The included unit tests in `common/src/normalized_transport.rs` assert that
the on‑wire bytes have the exact byte‑for‑byte structure of TLS 1.2
records, which is the same heuristic Wireshark uses to classify a flow as
`tls`. To verify on a live link:

```bash
# On the agent host (root required for raw capture).
sudo tcpdump -i any -w /tmp/orchestra.pcap 'host <controller-ip> and port 8443'

# Run a few commands from the console, then stop the capture.

# Confirm Wireshark/tshark classifies the flow as TLS.
tshark -r /tmp/orchestra.pcap -Y tls -T fields \
       -e _ws.col.Protocol -e tls.record.content_type -e tls.handshake.type \
   | head
```

Expected output with `traffic_profile = "tls"`:

```text
TLS  22  1   <- handshake / ClientHello
TLS  22  2   <- handshake / ServerHello
TLS  23      <- application_data
TLS  23      <- application_data
...
```

The Protocol column reports `TLS`, confirming Wireshark classifies the flow
as TLS based purely on its byte structure.
