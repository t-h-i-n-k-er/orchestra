# Orchestra User Guide

> A practical manual for IT administrators deploying and operating the
> **Orchestra** remote management framework.

---

## 1. Introduction

Orchestra is a lightweight, cross-platform remote-administration framework
written in Rust. It is intended for **authorized system administrators** who
need to:

- Inventory a fleet of servers, workstations, and IoT edge devices.
- Run pre-approved maintenance scripts.
- Collect diagnostic information (system info, log files).
- Push out signed configuration changes and capability plugins.
- Perform interactive troubleshooting via a remote shell — when authorized.

Orchestra is **not** an exploitation tool. Every operation is gated by either
a pre-shared secret or a mutually-authenticated TLS session, and every action
is recorded to a local audit log. Use of Orchestra against systems you do not
own or do not have written authorization to manage is forbidden by the
project license.

---

## 2. Installation

### 2.1 Building from source

Requirements: Rust **1.76+**, `pkg-config`, `libxcb-dev`, `libxrandr-dev`
(Linux only, for `remote-assist`), and a C compiler.

```bash
git clone https://github.com/example/orchestra
cd orchestra
cargo build --release --workspace
```

The binaries land in `target/release/`:

| Binary               | Purpose                                  |
|----------------------|------------------------------------------|
| `console`            | Operator CLI                              |
| `agent` (lib only)   | Library used by your own service wrapper  |

### 2.2 Pre-built binaries

Pre-built binaries for Linux x86_64, Windows x86_64, and macOS aarch64 are
attached to each tagged release on GitHub.

---

## 3. Setting up mTLS

For production use you should always operate with mutual TLS. Generate a
private CA, an agent certificate, and one client certificate per operator:

```bash
# CA
openssl req -x509 -newkey ed25519 -keyout ca.key -out ca.pem -days 365 \
    -nodes -subj "/CN=OrchestraCA"

# Agent server cert
openssl req -newkey ed25519 -keyout agent.key -out agent.csr -nodes \
    -subj "/CN=agent.example.com"
openssl x509 -req -in agent.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out agent.pem -days 365

# Operator client cert
openssl req -newkey ed25519 -keyout alice.key -out alice.csr -nodes \
    -subj "/CN=alice@example.com"
openssl x509 -req -in alice.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out alice.pem -days 365
```

Distribute `ca.pem` to every operator's workstation, install
`agent.pem`/`agent.key` on each managed endpoint, and give each operator
their own client cert/key pair.

---

## 4. Deploying the agent

Currently the agent is consumed as a library; embed it in a small wrapper
binary you build for your own organization. The wrapper is responsible for
configuring the listener and supplying the TLS credentials. A reference
launcher implementation is described in `docs/DESIGN.md` §"Agent Launcher
and In-Memory Deployment".

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

## 5. Basic commands

```bash
# TCP + pre-shared key (development)
console --target 10.0.0.5:7890 --key $(cat orchestra.key) ping

# mTLS (production)
console --target agent.example.com:7890 --tls \
        --ca-cert ca.pem \
        --client-cert alice.pem --client-key alice.key \
        info
```

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

Every command produces an `AuditEvent` that is delivered to the console as
a separate `AuditLog` message and appended to `audit.log` (JSON-lines).
The `user` field contains the operator identity propagated from the Control
Center session (or `"admin"` for direct console connections).
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
| `connection refused`                          | Agent not listening, firewall, or wrong port                       |
| `AES-GCM authentication failed`               | Pre-shared key mismatch                                            |
| `tls handshake failure: unknown ca`           | `--ca-cert` does not match the cert that signed the agent          |
| `Path is not under any allowed root`          | Add the directory to `allowed_paths` in `agent.toml`               |
| Plugin load fails with `ELF magic`            | Plugin built for the wrong target triple                           |

For deeper diagnostics, run the agent wrapper with
`RUST_LOG=debug,orchestra=trace` and check `audit.log` on the console
side.

---

## 10. Trusted Execution Environment Enforcement

Orchestra can abort startup if the agent detects it is running in an
untrustworthy environment — a debugger, a hypervisor, or a domain it was not
provisioned for.  This feature is intended for deployments where an operator
needs confidence that a captured binary cannot be trivially reverse-engineered
in an instrumented sandbox.

### Configuration knobs

Add either or both of the following keys to `agent.toml`:

```toml
# Only start normally if the machine's DNS/AD domain matches this string
# (case-insensitive).  Leave unset to skip the domain check.
required_domain = "corp.example.com"

# If true the agent enters dormant mode when a hypervisor is detected.
# If false (the default) a VM is allowed — useful if you deploy agents
# inside your own virtual estate.
refuse_in_vm = false
```

### What the enforcement module checks

| Check | Method |
|-------|--------|
| **Debugger present** | Linux: reads `TracerPid` from `/proc/self/status`; Windows: `IsDebuggerPresent()`, PEB.BeingDebugged, and PEB.NtGlobalFlag via inline assembly. |
| **Hypervisor / VM** | CPUID hypervisor bit (leaf 1, ECX bit 31); Linux: DMI strings (`vmware`, `virtualbox`, `kvm`, `qemu`, `xen`, `hyper-v`) from `/sys/class/dmi/id/`; Windows: registry entries under `HKLM\SYSTEM\CurrentControlSet\Services\{vmci,vboxguest,xen}`; MAC OUI prefixes associated with known VM vendors. |
| **Domain match** | Case-insensitive string comparison against `USERDNSDOMAIN` (Windows), `HKLM\…\Tcpip\Parameters\Domain` (Windows registry), or `/proc/sys/kernel/domainname` (Linux). |

### Dormant state

If any active check fails the agent logs a single error line and enters a
dormant sleep loop (waking every 3600 s, doing nothing) rather than exiting.
A sleeping process attracts less scrutiny than one that terminates with a
non-zero exit code.

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

`required_domain` and `refuse_in_vm` are runtime config; they do not need to
be set at build time.

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
