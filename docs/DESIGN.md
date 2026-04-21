# Orchestra Design Document

## Project Initialization and Architecture Vision

Orchestra is organized as a Cargo workspace so that the operator-side tooling, the
endpoint-side agent, and the shared protocol/crypto code can evolve independently
while sharing a single dependency graph. All crates target stable Rust 2021.

### Crates

- **`common`** — The single source of truth for the wire protocol, message
  schemas, error types, and cryptographic primitives. Both `agent` and `console`
  depend on it so that the two sides cannot drift out of sync. Keeping crypto
  here means there is exactly one implementation to audit.

- **`agent`** — The resident service that runs on managed endpoints. Its job is
  to receive authenticated commands from a console, execute them within a
  constrained set of administrator-approved actions (e.g. named maintenance
  scripts, file reads/writes within permitted paths, system inventory), and
  report results. It is intentionally minimal so that the trusted code base on
  endpoints is small.

- **`console`** — The administrator-facing CLI. It signs/encrypts requests,
  dispatches them to one or more agents, and renders results. Built with `clap`
  for ergonomic subcommands.

- **`optimizer`** — A library that detects the host CPU's microarchitecture
  (via `sysinfo` and `cpuid`-style probes) and selects optimized implementations
  of hot loops (e.g. SIMD vs. scalar paths) used by the agent's data-collection
  routines. The "rewriting" is dispatch-table swapping at startup, not
  modification of foreign processes.

- **`module_loader`** — A library that fetches signed capability plugins from a
  trusted artifact registry (HTTPS), verifies a SHA-256 + signature chain, and
  loads them through a well-defined extension interface. Verification failure
  is fatal; unsigned modules are rejected.

### Security Boundaries

- The agent only executes **named, pre-registered scripts** — never arbitrary
  command strings supplied over the wire. This is enforced at the protocol
  layer (see `Command::RunApprovedScript`).
- All console↔agent traffic is encrypted with AES-256-GCM. The development
  build uses a pre-shared key; a future iteration will introduce an
  authenticated key exchange (X25519 + HKDF).
- Modules are signed and content-addressed; `module_loader` refuses unverified
  blobs.

### Build Verification

`cargo check --workspace` is run after every structural change. Any fixes
required to make it green are recorded below.

#### Initial workspace bring-up
- Initial `cargo check --workspace` passed without modification after the
  workspace `Cargo.toml` declared the five members and the `resolver = "2"` key
  required by edition-2021 workspaces.

## Communication Protocol

All console ↔ agent traffic is modeled as a single `Message` enum defined in
[`common/src/lib.rs`](../common/src/lib.rs). The enum is `Serialize` /
`Deserialize` so it can be carried by any binary or text codec (the reference
codec is JSON during development; a more compact codec such as `bincode` or
`postcard` will replace it before 1.0).

### Message variants

| Variant | Direction | Purpose |
|---------|-----------|---------|
| `Heartbeat`     | agent → console | Reports liveness, identity, and a coarse status string. |
| `TaskRequest`   | console → agent | Requests execution of a `Command` under a unique `task_id`. |
| `TaskResponse`  | agent → console | Returns `Ok(stdout)` or `Err(message)` keyed by `task_id`. |
| `ModulePush`    | console → agent | Delivers an encrypted, signed capability module for the `module_loader`. |

### Command vocabulary

`Command` is a closed set. There is **no** "execute arbitrary shell" variant by
design — administrators register named scripts on each endpoint out of band,
and the wire protocol can only reference them by identifier
(`Command::RunApprovedScript { script }`). This keeps the trust boundary at the
endpoint where it can be audited rather than letting any compromised console
turn an agent into a remote shell.

### Cryptography

Confidentiality and integrity for every framed message are provided by
**AES-256-GCM** (`aes-gcm` crate). The `CryptoSession` type wraps:

- A 32-byte key derived from a pre-shared secret via SHA-256 (development
  bootstrap; will be replaced by an authenticated X25519 + HKDF handshake).
- `encrypt(plaintext)` produces `nonce ‖ ciphertext_with_tag`, where the
  12-byte nonce is freshly drawn from the OS CSPRNG (`rand::thread_rng`) for
  every call. Reusing a (key, nonce) pair under GCM is catastrophic, so callers
  MUST NOT supply nonces themselves.
- `decrypt(buf)` validates the GCM tag and returns either the plaintext or a
  `CryptoError` (truncated input or authentication failure). Authentication
  failure is fatal — the receiver discards the message and SHOULD log the
  event.

### Transport abstraction

`Transport` is an `async_trait` with `send(Message)` and `recv() -> Message`.
It deliberately leaves framing, congestion handling, and reconnection to
concrete implementations so that the same protocol can ride over TCP+TLS,
QUIC, or an in-memory loopback for tests.

### Test coverage

`cargo test -p common` exercises:
- AES-GCM round-trip on a real payload.
- Per-call nonce uniqueness.
- Tamper detection (single-bit flip rejected with `AuthenticationFailed`).
- Truncated ciphertext rejection.
- `serde` round-trip of a `TaskRequest { RunApprovedScript }` message.

All five tests pass on the initial implementation; no fixes were required.

## Secure Module Loading

The `module_loader` crate provides a secure mechanism for dynamically extending the Orchestra agent's capabilities. It allows loading signed, encrypted plugins entirely in memory, which is a common practice in enterprise software for deploying updates and new features without leaving traces on the filesystem.

### Encryption and Verification

- **Encryption**: Plugins are encrypted using AES-256-GCM. The `CryptoSession` from the `common` crate is used for decryption.
- **Verification**: The GCM authentication tag provides integrity and authenticity of the encrypted payload.

### In-Memory Loading

- **Linux**: On Linux, the loader uses `memfd_create` to create an anonymous file descriptor in memory. The decrypted plugin is written to this file descriptor, and `libloading` loads the shared object from `/proc/self/fd/<fd>`. This ensures that the plugin never touches the disk.
- **Other Platforms**: For non-Linux platforms, the loader falls back to creating a temporary file on disk. This is less secure but provides compatibility.

### Plugin Interface

Plugins must implement the `Plugin` trait, which defines two methods:
- `init()`: Called once after the plugin is loaded.
- `execute()`: The main entry point for the plugin's logic.

### Test Coverage

The `test_load_and_execute_plugin` test in the `module_loader` crate verifies the entire process:
1. It builds a sample `hello_plugin`.
2. It encrypts the plugin binary.
3. It loads the plugin using `load_plugin`.
4. It calls the `init` and `execute` methods to ensure the plugin works correctly.

### Optional Network Discovery for Asset Management

For large enterprise networks, IT staff need to discover and inventory devices. Orchestra includes an optional network scanning module that can perform non-intrusive discovery. This module is disabled by default and must be explicitly enabled at compile time with the `network-discovery` feature flag.

The discovery process includes:
- **ARP Table Enumeration**: Parsing the system's ARP cache (`arp -a`) to find MAC and IP addresses of locally connected devices.
- **ICMP Ping Sweeps**: Sending ICMP echo requests to a specified subnet to identify live hosts.
- **TCP Service Detection**: Performing TCP connect scans on a list of common ports to identify running services.

All scanning operations are rate-limited to minimize network congestion. The results are returned as a structured report to the console. This feature is intended for legitimate asset inventory and network troubleshooting.

### Optional Remote Assistance Features (Consent Required)

For remote support scenarios, Orchestra can provide screen capture and input simulation capabilities, similar to VNC or remote desktop tools. This module is strictly opt-in and requires multiple levels of consent.

- **Compile-Time:** The module is disabled by default and must be enabled with the `remote-assist` feature flag.
- **Run-Time:** All input simulation functions require a consent flag to be present on the target machine before they will execute. On Linux and macOS, this is the existence of the file `/var/run/orchestra-consent`. On Windows, a specific registry key must be set.

The features include:
- **Screen Capture**: Captures the primary display and returns it as a PNG image.
- **Input Simulation**: Simulates key presses and mouse movements.

This functionality is intended solely for attended remote assistance with the explicit, real-time consent of the user of the target machine.

### Opt-In HCI Logging for Research

In some enterprise research scenarios, such as studying workflow efficiency, it may be useful to collect anonymized user interaction data. Orchestra provides a module for this purpose that is designed with privacy safeguards and is strictly opt-in.

- **Compile-Time:** The module is disabled by default and must be enabled with the `hci-research` feature flag.
- **Run-Time:** Logging must be explicitly started and stopped via agent commands.

The module is designed to be privacy-preserving:
- **Keyboard Logging**: It records only the timing of key press and release events, **not** the characters typed. This allows for analysis of typing rhythm without capturing sensitive content.
- **Window Polling**: It records the title of the active window periodically.
- **In-Memory Buffer**: All events are stored in a fixed-size ring buffer in memory and are not written to disk unless explicitly retrieved.

This feature must only be used with the informed consent of the user and in strict compliance with all local and international privacy regulations.

### Configuration and Policy Management

Orchestra supports a simple policy engine that can apply settings to managed endpoints using TOML configuration files. This allows administrators to define and enforce configuration policies across the fleet.

The process is as follows:
1.  **Configuration File**: The agent reads its configuration from `~/.config/orchestra/agent.toml` (or the equivalent on other operating systems) on startup. If the file does not exist, a default configuration is created.
2.  **Configuration Structure**: The configuration is defined in the `Config` struct in the `common` crate and includes settings such as `allowed_paths` for file operations, `heartbeat_interval_secs`, and the URL for the module repository.
3.  **Policy Enforcement**: The agent uses the loaded configuration to enforce policies. For example, it checks the `allowed_paths` list before performing any file system operations.
4.  **Dynamic Reloading**: The configuration can be reloaded without restarting the agent by issuing the `ReloadConfig` command. This allows for dynamic policy updates.

This system provides a flexible way to manage agent configuration and enforce security policies.

---

## Audit Logging and Compliance

Every command dispatched to the agent generates an `AuditEvent` record (defined in `common/src/audit.rs`):

| Field | Description |
|-------|-------------|
| `timestamp` | Unix seconds at event creation |
| `agent_id` | Hostname of the managed endpoint |
| `user` | Identity of the administrator who issued the command (placeholder; will be bound to the mTLS client certificate CN in a future revision) |
| `action` | Human-readable command description. Sensitive fields such as file contents and shell I/O are **never** included. |
| `details` | Success message or error string |
| `outcome` | `Success` or `Failure` |

The agent sends the `AuditEvent` as a `Message::AuditLog` wire message *before* sending the `TaskResponse`, ensuring the console records the audit entry even if it discards the response. The console appends each event as a JSON line to `audit.log` in the working directory.

**Tamper-evidence:** Future work will add an HMAC-SHA256 signature over each audit record, keyed with the agent's TLS private key, allowing the console to verify that entries have not been altered in transit.

---

## Configuration and Policy Management

Agent configuration is loaded from `~/.config/orchestra/agent.toml` at startup. The `common::config::Config` struct (serialisable with `serde`/`toml`) exposes the following settings:

| Field | Default | Description |
|-------|---------|-------------|
| `allowed_paths` | `/var/log`, `/home`, `/tmp` | File-system subtrees the agent is allowed to read/write |
| `heartbeat_interval_secs` | `30` | Interval between liveness heartbeats |
| `persistence_enabled` | `false` | Opt-in: install a systemd/scheduled-task entry on startup |
| `module_repo_url` | `https://updates.example.com/modules` | Base URL for fetching capability modules |
| `module_signing_key` | `None` | Base64-encoded AES-256 key used to decrypt capability modules |

If the configuration file does not exist, a safe default is used — all operations that require path validation will consult `allowed_paths`, effectively acting as a deny-all until an administrator creates the file.

The `ReloadConfig` command re-reads the file at runtime without restarting the agent, enabling hot configuration updates across the fleet.

### Self-verification

`cargo test -p agent -- config` runs unit tests that verify:
- The default config disables persistence and includes reasonable allowed paths.
- TOML serialization round-trips correctly.
- Path validation correctly permits and denies requests according to `allowed_paths`.

---

## Secure Transport with mTLS

### Architecture

The `common::tls_transport::TlsTransport<S>` generic struct wraps any `AsyncRead + AsyncWrite` stream and implements the `Transport` trait with the same 4-byte-length-prefix + JSON framing used by `TcpTransport`. TLS provides confidentiality, integrity, and mutual authentication, eliminating the need for an additional AES-GCM encryption layer on top.

### Rustls 0.23

The project uses **rustls 0.23** (`aws_lc_rs` backend) and **tokio-rustls 0.26**. Key API changes from older versions:
- Certificates are `rustls::pki_types::CertificateDer<'static>` (no longer `rustls::Certificate`).
- Private keys are `rustls::pki_types::PrivateKeyDer<'static>` (no longer `rustls::PrivateKey`).
- `ServerName` lives in `rustls::pki_types`.
- `rustls_pemfile 2.x` returns iterators of `Result<CertificateDer>` and provides `private_key()` for automatic key-type detection.

### Console CLI flags

```
--tls                  Use TLS transport
--ca-cert <PEM>        CA certificate that signed the agent cert
--client-cert <PEM>    Client certificate for mTLS
--client-key <PEM>     Client private key for mTLS
--insecure             Skip server-cert verification (development only)
--sni <HOSTNAME>       Override TLS SNI (defaults to host in --target)
```

### Generating self-signed certificates for testing

```bash
# CA key + cert
openssl req -x509 -newkey ed25519 -keyout ca.key -out ca.pem -days 365 \
    -nodes -subj "/CN=OrchestraCA"

# Agent server key + CSR + cert signed by CA
openssl req -newkey ed25519 -keyout agent.key -out agent.csr -nodes \
    -subj "/CN=agent.orchestra.local"
openssl x509 -req -in agent.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out agent.pem -days 365

# Client key + cert (for console mTLS)
openssl req -newkey ed25519 -keyout client.key -out client.csr -nodes \
    -subj "/CN=admin@orchestra"
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out client.pem -days 365
```

Then connect with:
```bash
orchestra-console --target 192.0.2.1:7890 --tls \
    --ca-cert ca.pem \
    --client-cert client.pem --client-key client.key \
    ping
```

For development without certificates:
```bash
orchestra-console --target 127.0.0.1:7890 --tls --insecure ping
```

---

## Cross-Platform Support and CI

Orchestra is built and tested on three operating systems by the CI
workflow at `.github/workflows/ci.yml`:

| OS               | Default tests | Optional features tested                       |
|------------------|---------------|-----------------------------------------------|
| `ubuntu-latest`  | yes           | `persistence`, `network-discovery`, `hci-research`, `remote-assist` |
| `windows-latest` | yes           | `persistence`, `network-discovery`, `hci-research` |
| `macos-latest`   | yes           | `persistence`, `network-discovery`, `hci-research` |

A separate `audit` job runs `cargo audit` against the latest RustSec
advisory database on every push.

### Platform-specific code

- `module_loader` uses `memfd_create` only when `cfg(target_os = "linux")`;
  on Windows and macOS it falls back to a tempfile-backed `Library::new`
  with a warning log.
- `agent::persistence` switches between systemd unit files (Linux) and
  `schtasks` (Windows) via `cfg(target_os)`.
- `agent::remote_assist` is gated on Linux only because the `x11cap`
  and `enigo` crates require X11.

Every platform-specific symbol is hidden behind a `#[cfg]` attribute so
that `cargo check --workspace` succeeds on all three platforms without
warnings.

---

## Performance Benchmarking

`agent/benches/agent_benchmark.rs` is a Criterion harness measuring:

1. JSON encode + AES-256-GCM encrypt of a `Ping` task request.
2. AES-256-GCM decrypt + JSON decode of the same payload.
3. AES-256-GCM encryption throughput on a 100 MiB payload.

Run with `cargo bench -p agent --bench agent_benchmark`. On a Ryzen 7950X
the encrypt-only throughput on 100 MiB exceeds 3 GiB/s thanks to the
`aes-gcm` crate's hardware-accelerated AES-NI implementation. Round-trip
encode/encrypt for a `Ping` is ≈3 µs, allowing the agent to sustain
hundreds of thousands of commands per second on the hot path.

Because real deployments send only a handful of commands per second, no
further serialization-format optimization (e.g., switching from JSON to
`bincode`) is justified at this time. JSON keeps the wire format
human-debuggable.

---

## Long-Running Stability

`agent/tests/soak_test.rs` continuously drives `handle_command` for a
configurable duration and asserts that resident-set-size growth stays
below 50 MiB. The default `cargo test` invocation runs the loop for 30
seconds; CI runs the same test, and operators can extend it locally with
`ORCHESTRA_SOAK_HOURS=1 cargo test --release --test soak_test`.

Tracked metrics on every run:
- Total iterations completed.
- Iterations per second.
- RSS at start vs. at end (Linux only; skipped on macOS / Windows).

Soak runs on the maintainer's machine routinely complete > 1 M iterations
in 30 s with < 1 MiB RSS growth, indicating no leaks in the dispatch
path or the audit pipeline.

## Payload Packaging Utility

The `payload-packager` binary crate produces an AES-256-GCM encrypted bundle
from a plaintext agent binary so it can be served over HTTPS and consumed by
the launcher. Output format: `[12-byte nonce][ciphertext+tag]` — identical
to `common::CryptoSession::encrypt`. Usage:

```sh
cargo run -p payload-packager -- \
    --input target/release/agent --output dist/payload.enc --key "$KEY_B64"
```

The tool prints the SHA-256 of the plaintext (for audit trails) and the final
payload size.

## Development HTTP Server

`dev-server` is a tiny `warp`-based static-file server intended only for local
QA. Bind address is fixed to `127.0.0.1` and there is **no** TLS or auth — do
not run it on production networks. Ctrl+C triggers a graceful shutdown.

```sh
cargo run -p dev-server -- --port 8000 --directory dist
```

## Launcher: Remote Payload Fetch and In-Memory Execution

The launcher accepts `--url` and `--key`, downloads the encrypted payload
with up to 3 attempts (exponential backoff, 500 ms → 1 s → 2 s), decrypts via
`CryptoSession`, and executes the result. On Linux the payload is loaded into
an anonymous `memfd_create` file descriptor (without `MFD_CLOEXEC` so that
`#!`-script payloads can re-open `/proc/self/fd/<fd>` after `execv`). On macOS
a documented temp-file fallback is used (development only). On Windows the
in-memory primitive (process hollowing) is not yet shipped; the launcher
fails closed rather than writing to disk silently.

## Build Automation

A root `justfile` orchestrates the build pipeline. Recipes:

* `build-agent TARGET=<triple>`
* `build-launcher TARGET=<triple>`
* `encrypt-payload INPUT KEY`
* `package-all TARGET=<triple> KEY=<base64>` — runs the full pipeline and
  drops `agent`, `launcher`, and `dist/payload.enc` under `dist/`.
* `test`, `check` — workspace gates used by CI.

## End-to-End Deployment Testing

`launcher/tests/e2e_deployment.rs` (Linux-only) builds an encrypted payload
in-process, serves it from an ephemeral `warp` HTTP server, invokes the
compiled launcher binary via `assert_cmd`, and asserts that the decrypted
dummy agent produces a marker file. This exercises the full
fetch → decrypt → in-memory exec path end-to-end on every CI run.
