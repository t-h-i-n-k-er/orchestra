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

| Subcommand                    | Description                                           |
|-------------------------------|-------------------------------------------------------|
| `ping`                        | Round-trip liveness check                             |
| `info`                        | OS, hostname, CPU, memory, process count              |
| `shell`                       | Interactive PTY session                               |
| `upload <local> <remote>`     | Push a file (subject to `allowed_paths`)              |
| `download <remote> <local>`   | Pull a file                                           |
| `deploy <module-name>`        | Fetch + verify + load a capability plugin             |
| `reload-config`               | Re-read `agent.toml` without restarting               |

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

### 6.4 HCI logging (research, opt-in)

Compile with `--features hci-research`. Logs key-press *timestamps* (no
content) and active window titles to a bounded ring buffer. Must be
explicitly started with `StartHciLogging` and is disabled on every
restart. Use only in compliance with applicable privacy regulations.

---

## 7. Audit logging and monitoring

Every command produces an `AuditEvent` that is delivered to the console as
a separate `AuditLog` message and appended to `audit.log` (JSON-lines).
Sample entry:

```json
{"timestamp":1740000000,"agent_id":"web-01","user":"alice@example.com",
 "action":"ReadFile(/var/log/syslog)","details":"OK (4096 bytes)",
 "outcome":"Success"}
```

Pipe `audit.log` into your SIEM of choice (Splunk, Elastic, Loki, …).

---

## 8. Troubleshooting

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

## 9. Reporting security issues

Please email `security@example.com` with reproduction steps. Do **not**
file public issues for unfixed vulnerabilities.
