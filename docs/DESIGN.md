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
| `VersionHandshake` | agent → server (init), server → agent (echo) | Protocol version negotiation. Agent sends its version on connect; server echoes back. Mismatches log a warning. Current version: `2`. |
| `Heartbeat` | agent → console | Reports liveness, identity, and a coarse status string. |
| `TaskRequest` | console → agent | Requests execution of a `Command` under a unique `task_id`. Includes optional `operator_id` populated by the Control Center. |
| `TaskResponse` | agent → console | Returns `Ok(stdout)` or `Err(message)` keyed by `task_id`. |
| `ModulePush` | console → agent | Delivers an encrypted, signed capability module for the `module_loader`. |
| `AuditLog` | agent → console | Pushes an `AuditEvent` record for compliance logging. |
| `Shutdown` | either | Graceful session termination. |

### Command vocabulary

`Command` is a closed set. There is **no** "execute arbitrary shell command"
variant — the closest is `StartShell` which opens an interactive PTY session
that the agent itself manages. All file operations are constrained by
`allowed_paths`. The full command set:

| Command | Purpose |
|---------|---------|
| `Ping` | Liveness check. |
| `GetSystemInfo` | Host inventory (OS, arch, uptime, memory). |
| `RunApprovedScript { script }` | Execute a pre-registered named maintenance script (not an arbitrary command line). |
| `ListDirectory { path }` | List files within `allowed_paths`. |
| `ReadFile { path }` | Read file contents within `allowed_paths`. |
| `WriteFile { path, content }` | Write file within `allowed_paths`. |
| `DeployModule { module_id }` | Stage a capability module by ID from the module cache. |
| `ExecutePlugin { plugin_id, args }` | Execute a loaded plugin with arguments. |
| `StartShell` | Open an interactive PTY session (returns a `session_id`). |
| `ShellInput { session_id, data }` | Write bytes to a PTY session's stdin. |
| `ShellOutput { session_id }` | Poll a PTY session's stdout/stderr. |
| `CloseShell { session_id }` | Terminate a PTY session and free file descriptors. |
| `Shutdown` | Gracefully stop the agent. |
| `DiscoverNetwork` | Perform bounded subnet enumeration (requires `network-discovery` feature). |
| `CaptureScreen` | Capture the primary display as PNG (requires `remote-assist` feature). |
| `SimulateKey { key }` | Simulate a key press (requires `remote-assist` + consent). |
| `SimulateMouse { x, y }` | Simulate mouse movement (requires `remote-assist` + consent). |
| `StartHciLogging` | Begin HCI telemetry capture (requires `hci-research` feature). |
| `StopHciLogging` | Stop HCI telemetry capture. |
| `GetHciLogBuffer` | Drain buffered HCI events. |
| `ReloadConfig` | Re-read `agent.toml` at runtime without restarting. |
| `EnablePersistence` | Install the opt-in persistence service. |
| `DisablePersistence` | Remove the persistence service. |
| `MigrateAgent { target_pid }` | Migrate into another process (experimental, platform-gated). |
| `ListProcesses` | Return a JSON snapshot of running processes. |

### Cryptography

Confidentiality and integrity for every framed message are provided by
**AES-256-GCM** (`aes-gcm` crate) with **HKDF-SHA256** key derivation.
The `CryptoSession` type wraps:

- A 32-byte key derived from a pre-shared secret via **HKDF-SHA256** with a
  per-session random 32-byte salt. Protocol version 2 wire format:
  `salt(32) ‖ nonce(12) ‖ ciphertext_with_tag`. The nonce is freshly drawn
  from the OS CSPRNG (`rand::thread_rng`) for every call.
- `encrypt(plaintext)` produces `salt ‖ nonce ‖ ciphertext_with_tag`.
- `decrypt_with_psk(psk, wire_data)` extracts the embedded salt, derives
  the per-message key via HKDF, and decrypts. `decrypt()` handles both
  the new salt-prefixed format and a legacy `nonce ‖ ciphertext` format
  for backward compatibility.
- Authentication failure is fatal — the receiver discards the message and
  logs the event.

When the `forward-secrecy` feature is enabled, an **X25519** ephemeral
Diffie-Hellman exchange is performed after the TLS handshake to derive a
unique session key via HKDF, ensuring forward secrecy even if the PSK is
later compromised.

### Transport abstraction

`Transport` is an `async_trait` with `send(Message)` and `recv() -> Message`.
It deliberately leaves framing, congestion handling, and reconnection to
concrete implementations so that the same protocol can ride over TCP+TLS,
QUIC, or an in-memory loopback for tests. The on-wire codec is **bincode**
(not JSON) for compact framing; each frame is `u32 length prefix ‖ bincode-serialised Message`.

### Test coverage

`cargo test -p common` exercises:
- AES-GCM round-trip via `CryptoSession` with HKDF salt derivation.
- Per-call salt/nonce uniqueness across encryptions.
- Tamper detection (single-bit flip rejected with `AuthenticationFailed`).
- Truncated ciphertext rejection.
- `serde` round-trip of a `TaskRequest { RunApprovedScript }` message.
- `decrypt_with_psk` inter-operation between independently-created sessions.

## Secure Module Loading

The `module_loader` crate provides a secure mechanism for dynamically extending the Orchestra agent's capabilities. It allows loading signed, encrypted plugins entirely in memory, which is a common practice in enterprise software for deploying updates and new features without leaving traces on the filesystem.

### Encryption and Verification

- **Encryption**: Plugins are encrypted using AES-256-GCM. The `CryptoSession` from the `common` crate is used for decryption.
- **Verification**: The GCM authentication tag provides integrity and authenticity of the encrypted payload.

### In-Memory Loading

- **Linux**: On Linux, the loader uses `memfd_create` to create an anonymous file descriptor in memory. The decrypted plugin is written to this file descriptor, and `libloading` loads the shared object from `/proc/self/fd/<fd>`. This ensures that the plugin never touches the disk.
- **Windows (Manual Map)**: With the `manual-map` feature, a PE loader is used to map the DLL entirely in memory. It parses headers, copies sections, resolves imports, applies relocations, and calls the entry point without writing to a file.
- **Other Platforms**: For non-Linux platforms without manual mapping, the loader falls back to creating a temporary file on disk. This is less secure but provides compatibility.

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

### Module Signature Verification

To provide stronger integrity guarantees, module loading includes an optional Ed25519 signature check, enabled by the `module-signatures` feature (on by default).

**Packaging:**
- The `payload-packager` accepts an optional `--signing-key <private_key_file>` argument.
- If provided, it signs the plaintext module with the Ed25519 private key.
- The 64-byte signature is prepended to the module data before encryption: `[signature][module_data]`.

**Loading:**
- The `module_loader`, when the `module-signatures` feature is enabled, expects the signature to be present.
- It splits the decrypted payload into the signature and the module data.
- It verifies the signature against a hard-coded public key compiled into the agent.
- If verification fails, the module is rejected.

A `keygen` utility is provided to generate Ed25519 keypairs for module signing:
`cargo run --bin keygen -- --module-signing-key`

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

**Tamper-evidence:** Each audit record is signed with **HMAC-SHA256**, keyed with a
key derived from the admin token via `AuditLog::derive_hmac_key()`. The HMAC tag
is written as a paired line after each JSON entry. On read, `AuditLog::read_entries()`
verifies the tag and flags any tampered records.

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
| `module_cache_dir` | `~/.cache/orchestra/modules` (Unix) / `%LOCALAPPDATA%\Orchestra\modules` (Windows) | Directory from which `DeployModule` loads pre-staged module blobs |

If the configuration file does not exist, a safe default is used — all operations that require path validation will consult `allowed_paths`, effectively acting as a deny-all until an administrator creates the file.

The `ReloadConfig` command re-reads the file at runtime without restarting the agent, enabling hot configuration updates across the fleet.

### Self-verification

`cargo test -p agent -- config` runs unit tests that verify:
- The default config disables persistence and includes reasonable allowed paths.
- TOML serialization round-trips correctly.
- Path validation correctly permits and denies requests according to `allowed_paths`.

---

## Unified Filesystem Path Validation

Two divergent path-validation implementations previously coexisted —
one inside `agent/src/handlers.rs` (a naive `String::starts_with`
prefix check) and one inside `agent/src/fsops.rs` (which canonicalised
paths but ignored `config.allowed_paths` entirely, using a hard-coded
list instead). The two checks could disagree, so a request the
handler approved could still be rejected by `fsops` — or worse, a
crafted absolute prefix could slip past the handler check while a
symlink slipped past the `fsops` check.

The single source of truth is now [`fsops::validate_path`](../agent/src/fsops.rs):

```rust
pub async fn validate_path(path: &str, config: &Config) -> Result<PathBuf>;
```

Pipeline:

1. **Fast-path traversal rejection.** Any `..` component in the input
   is rejected before any filesystem I/O, eliminating the most common
   exfiltration pattern without paying for a `canonicalize` syscall.
2. **Canonicalisation in a blocking task.** `tokio::task::spawn_blocking`
   calls `std::fs::canonicalize`, which resolves all symlinks and
   produces an absolute path. When the target does not yet exist, the
   nearest existing ancestor is canonicalised and the missing tail is
   re-attached, so writes to *new* files inside an allowed directory
   still succeed.
3. **Allow-list comparison.** The canonical path must be a child of one
   of the canonicalised entries in `config.allowed_paths`. Roots that
   themselves fail to canonicalise (e.g. a path that doesn't exist on
   this host) are silently dropped — they cannot match any real path.

All file-operation handlers (`ListDirectory`, `ReadFile`, `WriteFile`,
`DeployModule`) now call `fsops::*` directly, and the handler-side
`is_path_allowed` helper has been removed.

### Test coverage (`fsops::tests`)

- A path inside the allowed directory is accepted and returned as its
  canonical form.
- A path containing `..` is rejected without touching the filesystem.
- A symlink that resides inside the allowed directory but points
  outside is rejected after canonicalisation.
- A non-existent path is accepted as long as its parent is allowed
  (the file operation itself reports the missing-file error).
- An empty `allowed_paths` list rejects everything.

## Secure `DeployModule`

The `DeployModule` handler used to construct a path by concatenating
the operator-supplied `module_id` with the literal string
`"./target/debug/lib"`. Two problems: a development-only path was
hard-coded into the production agent, and `module_id = "../../etc/passwd"`
trivially traversed out of it.

The hardened handler:

1. Validates `module_id` against `^[A-Za-z0-9_-]{1,128}$` via
   `is_valid_module_id` and rejects anything else.
2. Builds the on-disk path as
   `Path::new(&config.module_cache_dir).join(format!("{module_id}.so"))`.
3. Reads the blob through `fsops::read_file(path, &config)`, so the
   allow-list validation described above applies. Operators must
   include `module_cache_dir` in `allowed_paths` for deployment to
   succeed — the agent can no longer be tricked into reading a module
   from anywhere else.

### Test coverage (`handlers::tests`)

- `is_valid_module_id` accepts `hello_plugin`, `net-scan-v2`, `ABC123`
  and rejects `../../etc/passwd`, `foo/bar`, `foo.bar`, the empty
  string, and identifiers containing whitespace.
- `deploy_module_rejects_traversal_id` runs the full handler with
  `module_id = "../../etc/passwd"` and asserts the audit outcome is
  `Failure`.
- `deploy_module_reads_from_configured_cache_dir` stages a blob in a
  temporary `module_cache_dir`, adds the same dir to `allowed_paths`,
  invokes the handler, and asserts the failure (if any) comes from
  `module_loader::load_plugin` — i.e. the path validation layer
  permitted the read.

---

## Secure Transport with mTLS

### Architecture

The `common::tls_transport::TlsTransport<S>` generic struct wraps any `AsyncRead + AsyncWrite` stream and implements the `Transport` trait with the same 4-byte-length-prefix + **bincode** framing used by `TcpTransport`. TLS provides confidentiality, integrity, and mutual authentication, eliminating the need for an additional AES-GCM encryption layer on top.

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

| OS               | Default tests | Optional checks                                 |
|------------------|---------------|-------------------------------------------------|
| `ubuntu-latest`  | yes           | feature-module compile/tests, doc/feature drift, deterministic proc-macro tests |
| `windows-latest` | compile       | selected Windows-facing agent features and `module_loader/manual-map` compile |
| `macos-latest`   | compile       | selected macOS agent features when the Darwin toolchain is present |

### Platform-specific code

- `module_loader` uses `memfd_create` only when `cfg(target_os = "linux")`. On Windows, it can use a manual PE loader (`manual-map` feature) or fall back to a tempfile.
- `agent::persistence` switches between systemd unit files (Linux) and
  `schtasks` (Windows) via `cfg(target_os)`.
- `agent::remote_assist` is gated by the `remote-assist` feature. Linux X11 capture uses `x11cap`; macOS capture shells out to `screencapture` and validates PNG output; Windows capture currently returns an explicit unsupported error while input simulation remains consent-gated.
- `agent::process_manager` exposes process enumeration on all platforms. Migration paths are experimental, feature/permission-gated, and return explicit errors when prerequisites are not met.

Every platform-specific symbol is hidden behind a `#[cfg]` attribute so
that `cargo check --workspace` succeeds on all three platforms without
warnings.

### Dynamic Performance Tuning (Metamorphic Engine)

The `optimizer` crate contains a metamorphic engine that can dynamically rewrite function machine code at runtime to apply microarchitecture-specific optimizations.

1.  **Disassembly**: It uses the `iced-x86` crate to disassemble a function's code from a function pointer.
2.  **Transformation Passes**: It applies a series of transformation passes:
    *   **Instruction Substitution**: Replaces common instruction patterns with more efficient ones (e.g., `mov reg, 0` becomes `xor reg, reg`).
    *   **Dead Code Insertion**: Can insert `nop` instructions to alter the code's signature.
3.  **In-Memory Patching**: The engine makes the memory page containing the function's code writable (using `mprotect` on Unix or `VirtualProtect` on Windows), writes the new machine code, and then restores the original memory protections.
4.  **Verification**: A safe wrapper, `optimize_safely`, runs a test vector against the function before and after optimization to ensure the transformation did not alter its behavior. If the results differ, the original code is restored.

This functionality is integrated into the agent's startup sequence, where `optimize_hot_functions()` is called.

### Low-Level System Interface (Direct Syscalls)

Orchestra keeps the optional `direct-syscalls` feature as an experimental
Windows compatibility compile path. CI verifies that the feature compiles; the
strategy dispatcher routes through a shared bounded wrapper so stack arguments
and unsupported ABIs fail consistently.

Linux `aarch64` syscall path notes:

- The low-level wrapper supports up to 6 syscall arguments (the architectural
  calling convention limit for direct register-passed syscall args).
- Requests with more than 6 arguments are rejected with `EINVAL` instead of
  attempting stack-based argument marshalling.
- This fail-closed behavior is intentional to keep unsupported ABI shapes
  explicit and deterministic across platforms.

### In-Memory Plugin Deployment (Manual PE Mapping)

On Windows, the `module_loader` can use a true in-memory DLL loader when the `manual-map` feature is enabled, avoiding the use of temporary files.

1.  **PE Parsing**: It uses the `goblin` crate to parse the PE headers of the DLL byte array.
2.  **Manual Mapping**: It performs the steps of a manual PE loader:
    *   Allocates a memory region for the DLL image.
    *   Copies the PE sections into the allocated memory.
    *   Resolves function imports by looking up modules and functions in the current process.
    *   Applies base relocations if the DLL was loaded at a non-preferred address.
    *   Sets the correct memory protections on each section.
    *   Calls the DLL's entry point (`DllMain`) with `DLL_PROCESS_ATTACH`.
3.  **Integration**: The `load_plugin` function on Windows uses this manual loader, providing a fileless way to deploy and run plugins.

### Windows Support for Remote Assistance

The `remote-assist` feature compiles on Windows for consent-gated input
simulation. Screen capture returns a controlled unsupported error until the
platform capture integration is updated and covered by CI.

### Process Migration for Load Balancing (Process Hollowing)

`MigrateAgent` is treated as an experimental maintenance capability rather than
a default load-balancing path. Normal builds rely on process enumeration only;
migration-specific code is platform/permission gated and expected to fail
closed with a clear diagnostic when prerequisites are absent.

---

## Performance Benchmarking

`agent/benches/agent_benchmark.rs` is a Criterion harness measuring:

1. Bincode encode + AES-256-GCM encrypt of a `Ping` task request.
2. AES-256-GCM decrypt + Bincode decode of the same payload.
3. AES-256-GCM encryption throughput on a 100 MiB payload.

Run with `cargo bench -p agent --bench agent_benchmark`. On a Ryzen 7950X
the encrypt-only throughput on 100 MiB exceeds 3 GiB/s thanks to the
`aes-gcm` crate's hardware-accelerated AES-NI implementation. Round-trip
encode/encrypt for a `Ping` is ≈3 µs, allowing the agent to sustain
hundreds of thousands of commands per second on the hot path.

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

---

## Non-blocking Interactive Shell I/O

The interactive PTY shell exposed by `agent/src/shell.rs` originally
called `Read::read_to_end` on the master PTY inside `try_read_output`.
`read_to_end` blocks until EOF — i.e. until the child shell exits — so
the agent's worker thread froze the moment the operator opened a
shell, and no further `ShellInput` / `ShellOutput` commands could be
serviced. Worse, `read_to_end` would silently keep partial output
buffered into a `Vec` that was thrown away on every poll because it
never returned.

### Design

`ShellSession::new` spawns the child as before, takes the PTY writer
(which stays in ordinary blocking mode — input writes are tiny single
command lines and well-behaved), then clones the PTY reader and hands
it to a dedicated **reader thread**:

```
+---------------+        4 KiB chunks         +--------------------+
| PTY master fd | ───── blocking read() ───── | reader thread      |
+---------------+                             |   buf.extend(...)  |
                                              +---------+----------+
                                                        │
                                  Arc<Mutex<Vec<u8>>>   │
                                                        ▼
+--------------------+   try_read_output()   +---------------------+
|  agent dispatcher  | ────────────────────► | std::mem::take(buf) |
+--------------------+   never blocks        +---------------------+
```

- The thread loops on `read(&mut [0u8; 4096])`, appending whatever
  arrives to a shared `Arc<Mutex<Vec<u8>>>`. `Interrupted` errors are
  retried; any other error or `Ok(0)` (EOF) terminates the thread
  cleanly.
- `try_read_output` acquires the mutex, swaps the buffer out with
  `std::mem::take`, and returns. It never performs I/O on the hot
  path, so it cannot block the tokio worker.
- `Drop` kills the child via the saved `ChildKiller`, then joins the
  reader thread; closing the master PTY (when the writer is dropped)
  delivers EOF to the reader so the join completes promptly.

This approach is portable across Linux, macOS, and Windows and avoids
the per-platform `fcntl(O_NONBLOCK)` dance — `portable-pty`'s
`MasterPty::try_clone_reader` returns a `Box<dyn Read>` that does not
expose its raw file descriptor through the public trait, so reaching
in to flip flags would require a downcast onto a private type.

### Test coverage (`shell::tests`, Linux-only)

- `try_read_output_does_not_block` measures wall-clock time around a
  call against a freshly-created session and asserts it returns in
  under 200 ms (it should return effectively instantly).
- `echo_round_trip_in_chunks` spawns a shell, writes `echo hello\n`,
  and polls `try_read_output` in 20 ms intervals up to a 5 s deadline,
  accumulating chunks until `"hello"` appears in the output. This
  validates both that small reads stream through correctly and that
  the writer can deliver input while the reader thread is active.

### User Interaction Analytics (Workflow Optimization)

The Orchestra framework includes an optional module for collecting anonymized user interaction telemetry. This data helps system administrators and UX researchers understand application usage patterns and identify workflow inefficiencies across their managed fleet. The feature is strictly opt-in, requires explicit end-user consent, and is designed with privacy as a primary concern.

The purpose of this module is to help administrators understand peak usage times and frequently used applications for better resource planning. The data is anonymized and stored only in a temporary in-memory buffer; it is never transmitted automatically or written to disk. The feature is disabled by default and requires explicit end-user consent before any data is collected.

---

## Trusted Execution Environment Enforcement (`env_check`)

The `agent::env_check` module enforces that the agent binary is running inside an
approved execution context. This makes dynamic analysis (attaching a debugger,
running under a sandbox hypervisor) significantly harder.

### Checks performed by `enforce()`

| Check | Method | Detection criterion |
|-------|--------|---------------------|
| Debugger presence | `is_debugger_present()` | `/proc/self/status TracerPid` > 0 (Linux); `IsDebuggerPresent()` Win32 API (Windows) |
| Hypervisor / VM | `detect_vm()` | CPUID leaf 0x1 hypervisor bit; DMI strings; `/proc/cpuinfo` hypervisor flag |
| Active Directory domain | `validate_domain(required)` | `/etc/sssd/sssd.conf` or `/etc/krb5.conf` realm (Linux); `NetGetJoinInformation` (Windows) |

`enforce()` combines all three; if any check fails it returns
`Err(EnvReport { … })` describing which constraint was violated. The agent
`main.rs` calls `enforce()` before completing start-up when the
`env-validation` feature is enabled:

```rust
#[cfg(feature = "env-validation")]
if let Err(report) = env_check::enforce() {
    tracing::error!(?report, "TEE enforcement failed — exiting");
    std::process::exit(1);
}
```

### Adaptive VM Detection Thresholds

`detect_vm()` uses indicator counting with an adaptive threshold so cloud
deployments are less likely to be treated as analysis sandboxes.

- Tier 1 (`threshold = 2`): used when no cloud confirmation signal is present.
  This is the strict/default posture for unknown VMs.
- Tier 2 (`threshold = 3`): used when one cloud signal is present (expected
  cloud-hypervisor match and/or IMDS reachability). Expected hypervisor
  families include provider-context VM stacks such as VMware, VirtualBox, KVM,
  Hyper-V, and Xen.
- Tier 3 (`threshold = 4`): used when cloud confirmation is strongest (both
  expected-hypervisor and IMDS checks succeed). In practice this tier is
  commonly paired with `cloud_instance_id` allowlisting; a configured
  instance-id match can bypass VM refusal on known trusted instances.

Edge case:

- If IMDS is unavailable **and** the hypervisor name is not in the built-in or
  operator-extended expected list, the logic falls back to Tier 1
  (`threshold = 2`).
- A legitimate niche cloud VM may therefore still be flagged as VM when enough
  generic indicators accumulate.
- Recommended mitigation: set `cloud_instance_id` in configuration and add
  provider-specific strings via `vm_detection_extra_hypervisor_names` so
  `is_expected_hypervisor()` can classify the platform correctly.

### Cloud Whitelisting Fallback Controls

The env-validation policy now includes additional cloud-allowlisting controls:

- `cloud_instance_allow_without_imds`: permits VM-refusal bypass when IMDS is
  reachable/validated but instance-id parsing is unavailable.
- `cloud_instance_fallback_ids`: fallback instance-id pattern list used when
  IMDS instance-id retrieval fails (for example due to metadata firewalls).
- `vm_detection_extra_hypervisor_names`: operator-supplied hypervisor name
  fragments added to expected-hypervisor matching (Linux DMI product-name
  checks) without requiring code changes.

These controls are intentionally opt-in because they trade strict identity
binding for higher tolerance to provider/network metadata edge cases.

### Test coverage

Five unit tests cover the public API: `enforce_returns_ok_in_test_env`,
`is_debugger_present_returns_bool`, `detect_vm_returns_bool`,
`validate_domain_empty_required_always_ok`,
`validate_domain_impossible_domain_fails`.

---

## Windows Process Hollowing (`hollowing` crate)

The `hollowing` crate exposes a single cross-platform entry point:

```rust
pub fn hollow_and_execute(payload: &[u8]) -> anyhow::Result<()>
```

On non-Windows targets the function returns
`Err(anyhow!("only available on Windows"))`, which lets the entire workspace
compile on Linux and macOS without conditional compilation at the call site.

### Windows implementation (`src/windows_impl.rs`)

1. `CreateProcess` spawns `svchost.exe` in `PROCESS_CREATION_SUSPENDED` state.
2. `NtUnmapViewOfSection` unmaps the host process's image from the child.
3. `VirtualAllocEx` allocates RWX memory in the child at the preferred PE base.
4. `WriteProcessMemory` copies headers and each section.
5. `SetThreadContext` patches `Rcx`/`Eax` (entry point) in the primary thread's
   context.
6. `ResumeThread` starts execution.

The `launcher` crate's `execute_in_memory` function calls
`hollowing::hollow_and_execute(payload)` on Windows and falls back to a
temp-file execution path on other platforms.

### Test coverage

`launcher/tests/hollowing_test.rs` contains:
- `hollow_and_execute_returns_controlled_error_off_windows` (Linux/macOS):
  asserts the function returns `Err` containing the string
  `"only available on Windows"`.
- `hollow_and_execute_runs_a_dummy_exe` (Windows, `#[ignore]`): marked
  for manual execution on a Windows CI node.

---

## Builder Runtime Feature Discovery

`builder::config::read_agent_features()` parses `agent/Cargo.toml` using the
`toml` crate and extracts the `[features]` table at run time. This ensures the
interactive `configure` command and the `build_payload` function always reflect
the current feature set without needing manual synchronisation.

`partition_features(requested, known)` splits the user-requested features into
two sets: features present in `agent/Cargo.toml` (`effective`) and features
absent (`unknown`). Unknown features emit a `tracing::warn!` and are excluded
from the Cargo invocation to prevent build failures.

### Test coverage (`builder::config::tests`)

- `read_agent_features_matches_real_cargo_toml`: reads the real
  `agent/Cargo.toml` and asserts at least the well-known features are present.
- `partition_features_splits_known_and_unknown`: exercises the partition
  logic with a synthetic feature set.


