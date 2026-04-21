# Orchestra

**Orchestra** is a cross-platform, memory-efficient remote management framework
for enterprise device fleets. It gives IT and DevOps teams a single
authenticated control plane for executing approved maintenance tasks, deploying
software updates, collecting diagnostics, and auditing every operator action
across Linux, Windows, and macOS endpoints.

Orchestra is designed for organisations that need to administer systems they
own or manage — laptop fleets, build farms, VDI hosts, kiosks, edge gateways,
and similar IT estates.

## Why Orchestra

- **Lightweight on the endpoint.** The agent is a single statically-linked
  Rust binary. No background runtime, no daemon framework, minimal RSS.
- **Cross-platform.** First-class targets: `x86_64-unknown-linux-gnu`,
  `x86_64-pc-windows-gnu`, and `x86_64-apple-darwin`. ARM64 variants build
  from the same sources.
- **Authenticated end-to-end.** AES-256-GCM session encryption with random
  per-frame nonces, optional mTLS, bearer-token operator auth, and
  append-only JSONL audit logs.
- **Opt-in capability model.** Every non-default capability (persistence,
  network discovery, remote assistance, etc.) is a Cargo feature flag
  baked into a profile — only what you opt in to ships in the binary.
- **Self-hosted control plane.** The Orchestra Control Center
  (`orchestra-server`) gives you an HTTPS dashboard and REST API on
  infrastructure you control.

## Workspace layout

| Crate | Kind | Purpose |
|-------|------|---------|
| `agent` | lib + bin | Agent service that runs on managed endpoints. Can be embedded by the launcher or built standalone via the `agent-standalone` binary. |
| `console` | bin | Operator CLI for direct point-to-point sessions with a single agent. |
| `orchestra-server` | bin | **Orchestra Control Center** — self-hosted management plane fronting a fleet of agents over an HTTPS dashboard and REST/WebSocket API. See [docs/C_SERVER.md](docs/C_SERVER.md). |
| `builder` | bin | One-stop CLI for dependency setup, profile management, cross-compilation, and AES-encrypting payloads. See [builder/README.md](builder/README.md). |
| `launcher` | bin | Tiny stub that fetches and decrypts an agent payload at runtime. |
| `dev-server` | bin | Local HTTPS server for serving payloads to a launcher during testing. |
| `payload-packager` | bin | Stand-alone AES-256-GCM payload encryptor. |
| `common` | lib | Protocol types, transport, audit, and crypto primitives shared by every binary. |
| `optimizer` | lib | Runtime tuning of hot paths based on detected CPU microarchitecture. |
| `module_loader` | lib | Securely fetches, verifies, and loads signed capability plugins. |

## Quick start

### One-command quickbuild (recommended)

For a fresh Linux host that has nothing but `bash`, `git`, and an internet
connection, the [`scripts/quickbuild.sh`](scripts/quickbuild.sh) helper does
everything end-to-end: install Rust if missing, build the Builder, create a
default profile, build a payload, and start the dev server.

```sh
git clone https://github.com/example/orchestra.git
cd orchestra
./scripts/quickbuild.sh
```

Windows hosts can use [`scripts/quickbuild.bat`](scripts/quickbuild.bat) from
a `cmd.exe` prompt with the same effect.

The script prints the exact `launcher` command line to run on a target
endpoint when it finishes — copy it to your test VM and you're done.

Two environment variables let you customise without editing the script:

| Variable | Default | Effect |
|----------|---------|--------|
| `ORCHESTRA_QUICKBUILD_PROFILE` | `quickbuild` | Profile name to create / re-use under `profiles/`. |
| `ORCHESTRA_QUICKBUILD_PORT`    | `8000`       | Port the bundled `dev-server` binds to. |

### Interactive setup wizard

If you'd rather be walked through every choice (target OS, deployment
style, address, features, credentials, TLS, server bring-up) instead of
accepting defaults, use the step-by-step wizard:

```sh
./scripts/setup.sh
```

It asks for the target OS (`linux` / `windows` / `macos`), architecture,
deployment style (self-contained outbound `.exe` vs launcher + payload),
the Control Center address (LAN IP auto-detected), and any optional
feature flags. It then mints strong credentials, generates a self-signed
TLS cert covering the chosen address, writes both the agent profile and
`orchestra-server.toml`, cross-compiles the payload (falling back to
`cargo-zigbuild` when `mingw-w64` isn't installed for Windows builds),
and optionally starts the Control Center.

### Build the Builder from source

If you prefer to drive each step manually:

```sh
git clone https://github.com/example/orchestra.git
cd orchestra
cargo build --release -p builder
# Optional: put the binary on your PATH
install -m 0755 target/release/orchestra-builder /usr/local/bin/
```

> **Note.** Orchestra is currently distributed as source. A `cargo install
> orchestra-builder` shortcut is on the roadmap once the workspace is
> published to a registry; until then, building from source is the
> supported path.

## Step-by-step tutorial

The full tutorial below walks you through producing a signed agent payload,
launching the Control Center, and issuing a command from the dashboard.

### 1. Verify build dependencies

```sh
orchestra-builder setup
# or, to let it install missing Rust targets automatically:
orchestra-builder setup --auto-install
```

`setup` checks for `cargo`/`rustup`, a C toolchain, `pkg-config`, optional
cross-compilation toolchains (`mingw-w64` for Windows targets), and the
required Rust targets. It prints copy-paste install hints for anything it
finds missing. It never runs `sudo` on its own.

### 2. Create a profile

```sh
orchestra-builder configure --name my_agent
```

The interactive wizard asks for the values below. None of them are required
to be exotic — for a first build, accepting defaults targeting the current
host is fine.

| Option | What it controls |
|--------|------------------|
| `target_os` | Operating system to compile for (`linux`/`windows`/`macos`). |
| `target_arch` | CPU architecture (`x86_64`/`aarch64`). |
| `c2_address` | `host:port` the agent should connect or listen on. |
| `encryption_key` | Base64 AES-256 key used to encrypt the payload at rest. The wizard can generate one for you. |
| `features` | Cargo feature flags to enable on the agent (see "Feature flags" below). |
| `package` / `bin_name` | Which workspace crate/binary to build (defaults to `launcher`; set to `agent` / `agent-standalone` for outbound mode). |
| `c_server_secret` | Pre-shared secret used by `outbound-c` agents to authenticate to the Control Center. |

The result is written to `profiles/my_agent.toml` and can be edited by hand
or re-used in CI.

### 3. Build the payload

```sh
orchestra-builder build my_agent
# -> dist/my_agent.enc
```

The Builder cross-compiles the selected crate, optionally strips it, then
AES-256-GCM-encrypts the binary into `dist/<profile>.enc`. The output is
ready to be served by the dev-server (or any HTTPS file host) and consumed
by a launcher.

### 4. Start the Control Center

In a separate terminal:

```sh
cargo run --release --bin orchestra-server -- \
    --config orchestra-server/example-config.toml
```

On first run the Control Center generates a self-signed TLS certificate
and prints the bearer token it expects from the dashboard. For production
use, supply real `tls_cert_path` / `tls_key_path` values in the config and
front it with a reverse proxy. Full setup notes live in
[docs/C_SERVER.md](docs/C_SERVER.md).

The dashboard is then reachable at `https://127.0.0.1:8443/`. Log in by
pasting the bearer token from the config file.

### 5. Deploy the agent on a test endpoint

You have two deployment styles, picked by the profile:

#### a) Launcher + payload (default)

The launcher is a small stub; the agent payload is downloaded and
decrypted in memory. This is the default profile output.

```sh
# Serve dist/my_agent.enc over HTTP on port 8000.
cargo run --release -p dev-server -- --port 8000

# On the target endpoint:
launcher --url http://YOUR-HOST:8000/my_agent.enc \
         --key '<base64-key-from-profile>'
```

#### b) Standalone outbound agent (`outbound-c` feature)

When you build with `features = ["outbound-c"]`, the resulting binary
dials the Control Center directly with the address and PSK baked in at
compile time:

```sh
# On the target endpoint:
./agent-standalone
# (No flags needed — address is already baked in.
#  Override at runtime with ORCHESTRA_C / ORCHESTRA_SECRET if required.)
```

### 6. Issue commands from the dashboard

1. Open `https://YOUR-HOST:8443/` and authenticate with the bearer token.
2. Your registered agent appears in the **Agents** table within a few
   seconds of starting on the endpoint.
3. Use the **Send command** form to dispatch a `Ping`, shell command, or
   diagnostic request.
4. Every operator action is recorded to the JSONL audit log
   (`audit_log_path` in the server config) and broadcast over the
   `/api/ws` WebSocket for live tailing.

## Feature flags (performance & compatibility optimisations)

Orchestra ships with a set of opt-in Cargo features that tune the agent
for specific deployment environments. They are off by default; turn them
on per profile only when you need them.

| Feature | Purpose |
|---------|---------|
| `persistence` | Re-launches the agent across reboots using the platform-native auto-start mechanism (systemd user unit / launchd / scheduled task). Useful for fleet endpoints that should reconnect without operator intervention. |
| `network-discovery` | Enables passive subnet enumeration so the agent can report neighbouring hosts back to the Control Center for inventory. |
| `remote-assist` | Adds optional screen-share/keyboard-forwarding capability for IT support sessions (Linux only; pulls in `x11cap`/`enigo`/`image`). |
| `hci-research` | Instruments human-computer-interaction telemetry (input latency, focus changes) for usability studies — disabled in normal IT deployments. |
| `perf-optimize` | Enables CPU-microarchitecture-aware tuning paths in `optimizer`. Improves throughput on modern x86_64 hosts. |
| `outbound-c` | Switches the agent into outbound mode so it dials the Control Center automatically and reconnects with exponential backoff. See [docs/C_SERVER.md](docs/C_SERVER.md). |
| `traffic-normalization` | Normalises packet timing/sizes on the agent ↔ console transport for environments with strict QoS or DPI middleboxes. |
| `direct-syscalls` / `manual-map` | Compatibility shims for environments where the standard `libc` / loader paths trip endpoint-protection heuristics. |
| `env-validation` | Runs a startup Trusted Execution Environment (TEE) check on every launch. If a debugger, known hypervisor, or a domain mismatch is detected the agent enters a dormant sleep loop instead of running. Controlled via `required_domain` and `refuse_in_vm` in `agent.toml`. See [docs/USER_GUIDE.md §10](docs/USER_GUIDE.md) for full details. |

Run `orchestra-builder show-profile <name>` to inspect which features a
profile enables.

## Security best practices

- **Use real TLS material.** The Control Center generates a self-signed
  certificate on first run for convenience. In production, supply
  `tls_cert_path` / `tls_key_path` and front the dashboard with a
  reverse proxy (nginx, Caddy, Traefik) that terminates a publicly
  trusted certificate.
- **Prefer mTLS for agent ↔ server traffic.** The
  `common::tls_transport::TlsTransport` module is a drop-in replacement
  for the AES-only path and validates client certificates against your
  internal CA. Keep the AES-PSK transport for lab/test only.
- **Rotate keys.** Profiles store an AES-256 key; treat it as a secret
  and rotate it periodically. The Builder accepts `file:/path/to/key.bin`
  references so you can keep the key out of the profile TOML and source
  control.
- **Restrict the bearer token.** `orchestra-server.toml` holds a single
  `admin_token`. Store it in a secrets manager (Vault, AWS Secrets
  Manager, etc.) and inject it at deploy time. The token is compared in
  constant time, but a leaked token still grants full operator access.
- **Pin the audit log.** `audit_log_path` should live on a partition with
  restrictive permissions (e.g. `0640 root:orchestra`) and be shipped to
  your SIEM. Every operator-issued command and every agent-pushed
  `AuditLog` event is recorded there.
- **Limit allowed paths.** The agent's `allowed_paths` config restricts
  which directories `fsops` will read or write. Keep this list as narrow
  as the use case permits.
- **Sign your modules.** The `module_loader` crate verifies plugin
  signatures against `module_signing_key`. Never deploy with signature
  verification disabled.

## Documentation

- [docs/USER_GUIDE.md](docs/USER_GUIDE.md) — operator handbook.
- [docs/DESIGN.md](docs/DESIGN.md) — architecture and protocol notes.
- [docs/C_SERVER.md](docs/C_SERVER.md) — Control Center deployment
  reference (REST API, audit, outbound agents).
- [docs/LAUNCHER.md](docs/LAUNCHER.md) — Launcher in-memory execution,
  Windows process hollowing, and per-platform primitives.
- [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) — internal security
  review notes.
- [builder/README.md](builder/README.md) — Builder CLI reference.
- [console/README.md](console/README.md) — Console subcommand reference.
- [ROADMAP.md](ROADMAP.md) — planned work.

## Disclaimer

This software is intended for **authorised administration of systems you
own or manage**. Operators are responsible for ensuring their use of
Orchestra complies with all applicable laws, regulations, contracts, and
organisational policies. Misuse — including any deployment on systems
without explicit authorisation from their owner — is prohibited.

## License

Apache-2.0. See each crate's `Cargo.toml` for the per-crate licence
declaration.
# Orchestra

Orchestra is a secure, lightweight remote automation framework for enterprise IT management. It enables system administrators to execute approved maintenance tasks, deploy software updates, and collect diagnostic data across a heterogeneous fleet of devices without persistent installation or file-system clutter.

## Workspace Layout

| Crate | Kind | Purpose |
|-------|------|---------|
| `agent` | lib | Lightweight resident service running on managed endpoints. |
| `console` | bin | Operator CLI used by system administrators. |
| `orchestra-server` | bin | **Orchestra Control Center** — self-hosted management plane that fronts a fleet of agents over an authenticated HTTPS dashboard. See [`docs/C_SERVER.md`](docs/C_SERVER.md). |
| `common` | lib | Shared data structures, protocol definitions, and encryption utilities. |
| `optimizer` | lib | Runtime performance tuning for hot code paths based on detected CPU microarchitecture. |
| `module_loader` | lib | Securely fetches, verifies, and loads signed capability plugins. |

## Status

Early-stage scaffolding. See [`docs/DESIGN.md`](docs/DESIGN.md) for architecture notes.
