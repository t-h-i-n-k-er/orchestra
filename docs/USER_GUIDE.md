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
## Transport compatibility

The supported agent transport is the outbound Control Center channel:
`agent-standalone` connects to `orchestra-server`, validates TLS (with
certificate pinning when configured), then uses the authenticated message
protocol. The `traffic-normalization` feature remains an experimental library
compatibility flag and is not a documented deployment mode for stock agents.
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

A minimal `~/.config/orchestra/agent.toml` looks like:

```toml
allowed_paths = ["/var/log", "/etc/orchestra", "/home"]
heartbeat_interval_secs = 30
persistence_enabled = false
module_repo_url = "https://updates.internal.example.com/modules"
# module_signing_key = "<base64 AES-256 key>"
```

If the file does not exist the agent uses safe defaults.

---

## 5. Basic operations

Open the dashboard at `https://<server>:<http_port>/`, authenticate with
`admin_token`, then select a connected agent and submit one of the approved
commands. The legacy `console` binary remains useful for protocol testing
against custom listeners, but the stock `agent-standalone` binary does not
listen for direct console connections.

| Subcommand                           | Description                                                  |
|--------------------------------------|--------------------------------------------------------------|
| `ping`                               | Round-trip liveness check                                    |
| `info`                               | OS, hostname, CPU, memory, process count                     |
| `shell`                              | Interactive PTY session                                      |
| `upload <local> <remote>`            | Push a file (subject to `allowed_paths`)                     |
| `download <remote> <local>`          | Pull a file                                                  |
| `deploy <module-name>`               | Fetch + verify + load a capability plugin                    |
| `reload-config`                      | Re-read `agent.toml` without restarting                      |
| `discover`                           | LAN/host enumeration on the agent's network segment          |
| `screenshot [--out FILE]`            | Capture and save the primary display (`screenshot.png`)      |
| `key <K>` / `key --repl`             | Single key press, or stdin REPL (one key per line)           |
| `mouse X Y` / `mouse --repl`         | Mouse move, or stdin REPL (`x y` pairs per line)             |
| `hci-start` / `hci-stop`             | Start or stop the Bluetooth HCI log buffer                   |
| `hci-log`                            | Drain buffered HCI events                                    |
| `persist-enable` / `persist-disable` | Install or remove the agent's auto-start service             |
| `list-procs`                         | JSON snapshot of the running process table                   |
| `migrate <pid>`                      | Migrate the agent into `<pid>` via Windows process hollowing |

---

## 6. Advanced features

### 6.1 Plugin deployment

Plugins are signed shared libraries decrypted and loaded entirely in
process memory (`memfd_create` on Linux, mapped file on Windows/macOS).
See `docs/DESIGN.md` §"Secure Module Loading".

### 6.2 Persistence (opt-in)

Enable with `persistence_enabled = true` in `agent.toml`. The agent will
install a per-user systemd unit (Linux) or a scheduled task (Windows) at
startup. Disable by setting the flag to `false` and re-running
`reload-config`.

### 6.3 Remote assistance (opt-in, consent-gated)

Compile the agent with `--features remote-assist`. Input simulation is
**only** permitted while the consent file
`/var/run/orchestra-consent` (Linux) or registry value
`HKLM\Software\Orchestra\Consent` (Windows) exists.

### 6.4 Network discovery (opt-in)

Compile with `--features network-discovery`.  Adds the `DiscoverNetwork`
command, which returns ARP-table entries for the local segment parsed
directly from `/proc/net/arp` (Linux) or from `arp -a` on other
platforms.  A separate TCP-based "ping sweep" is available via the
`net_discovery` module API for automated inventory tasks.  Only complete
ARP entries (flag `0x2` on Linux) are returned; incomplete and static
placeholder entries are skipped.

### 6.5 Forward secrecy (opt-in)

Compile with `--features forward-secrecy`.  Before any application
message is sent, the agent and server perform an ephemeral X25519 key
exchange (see `C_SERVER.md` §"Forward secrecy").  This ensures that a
passive observer who later learns the pre-shared secret cannot decrypt
previously recorded traffic.

### 6.6 HCI logging (opt-in, research builds)

Compile with `--features hci-research`.  Logs key-press *timestamps*
(no content) and active window titles to a bounded ring buffer.  Must
be explicitly started with `StartHciLogging` and is disabled on every
restart.  Use only in compliance with applicable privacy regulations and
with explicit written consent from the affected users.

---

## 7. Encryption keys and the Builder

The Builder (`orchestra-builder configure`) generates a
**cryptographically random 32-byte AES-256 key** using `/dev/urandom`
and stores it as base64 in the profile TOML.  You should never copy a
key from an example, documentation, or test file into a production
profile.

The Builder will emit a `WARN`-level log message during `build` if it
detects an obviously weak key (all-zero bytes, all-identical bytes, or
sequential bytes).  That warning is a hard signal to regenerate the key
before deploying:

```bash
cargo run --release -p builder -- configure --name my-profile
# -> generates a random key automatically
cargo run --release -p builder -- build my-profile
```

To regenerate only the key for an existing profile:

```bash
cargo run --release -p builder -- key-rotate my-profile
```

---

## 8. Audit logging and monitoring

Every command produces an `AuditEvent` that is appended to the Control
Center audit log (JSON-lines). The `user` field contains the operator
identity propagated from the authenticated Control Center session.
Sample entry:

```json
{"timestamp":1740000000,"agent_id":"web-01","user":"alice@example.com",
 "action":"ReadFile(/var/log/syslog)","details":"OK (4096 bytes)",
 "outcome":"Success"}
```

Pipe `audit.log` into your SIEM of choice (Splunk, Elastic, Loki, …).

---

## 9. Troubleshooting

| Symptom                                        | Likely cause                                                       |
|-----------------------------------------------|--------------------------------------------------------------------|
| `connection refused`                          | Control Center agent port unreachable, firewall, or wrong port     |
| `AES-GCM authentication failed`               | Pre-shared key mismatch                                            |
| `tls handshake failure`                       | Server certificate pin mismatch or TLS material problem            |
| `Path is not under any allowed root`          | Add the directory to `allowed_paths` in `agent.toml`               |
| Plugin load fails with `ELF magic`            | Plugin built for the wrong target triple                           |

For deeper diagnostics, run the agent and server with
`RUST_LOG=debug,orchestra=trace` and check the server audit log.

---

## 10. Trusted Execution Environment Enforcement

Orchestra can collect startup environment signals and, when explicitly
configured, refuse startup on selected policy violations. The default policy
is low-false-positive: VM, tracer-process, debugger, timing, and sandbox
signals are informational unless a matching config knob is enabled.

### Configuration knobs

Add any of the following keys to `agent.toml`:

```toml
# Only start normally if the machine's DNS/AD domain matches this string
# (case-insensitive).  Leave unset to skip the domain check.
required_domain = "corp.example.com"

# If true the agent enters dormant mode when a hypervisor is detected.
# If false (the default) a VM is allowed — useful if you deploy agents
# inside your own virtual estate.
refuse_in_vm = false

# If true the agent refuses startup only when a debugger is attached to
# the agent process itself. Unrelated same-user processes named gdb/strace
# remain informational.
refuse_when_debugged = false

# Optional combined sandbox score threshold. Leave unset to make the score
# telemetry-only.
sandbox_score_threshold = 80
```

### What the enforcement module checks

| Check | Method |
|-------|--------|
| **Debugger present** | Linux: reads `TracerPid` from `/proc/self/status`; Windows: `IsDebuggerPresent()`, PEB.BeingDebugged, and PEB.NtGlobalFlag. Refusal requires `refuse_when_debugged = true`. |
| **Hypervisor / VM** | CPUID hypervisor bit (leaf 1, ECX bit 31); Linux: DMI strings (`vmware`, `virtualbox`, `kvm`, `qemu`, `xen`, `hyper-v`) from `/sys/class/dmi/id/`; Windows: registry entries under `HKLM\SYSTEM\CurrentControlSet\Services\{vmci,vboxguest,xen}`; MAC OUI prefixes associated with known VM vendors. |
| **Domain match** | Case-insensitive string comparison against `USERDNSDOMAIN` (Windows), `HKLM\…\Tcpip\Parameters\Domain` (Windows registry), or `/proc/sys/kernel/domainname` (Linux). |
| **Sandbox score** | Combined heuristic score from timing, resource, container, debugger, and VM indicators. Refusal requires `sandbox_score_threshold`. |

### Dormant state

If any configured refusal policy fails, the agent logs a single error line
and enters a dormant sleep loop (waking every 3600 s, doing nothing) rather
than continuing with management actions.

```
[ERROR] environment check failed — entering dormant state
```

Normal startup is logged at `INFO` level:

```
[INFO]  environment check passed (debugger=false vm=false domain=Some(true))
```

### Integration with the Builder

The `env-validation` Cargo feature enables the enforcement at compile time.
Enable it in your profile to bake the check into a payload:

```sh
orchestra-builder configure --name hardened_windows
# → select `env-validation` in the feature picker
orchestra-builder build hardened_windows
```

`required_domain`, `refuse_in_vm`, `refuse_when_debugged`, and
`sandbox_score_threshold` are runtime config; they do not need to be set at
build time.

---

## 11. Reporting security issues

Please email `security@example.com` with reproduction steps. Do **not**
file public issues for unfixed vulnerabilities.

---

## Network Compatibility Layer

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
