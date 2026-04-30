# Architecture

This document describes Orchestra's internal design: the workspace structure,
wire protocol, cryptographic primitives, transport abstraction, module loading,
and configuration system.

---

## Workspace structure

Orchestra is a Cargo workspace with 24 crates grouped by role:

| Crate | Role | Description |
|-------|------|-------------|
| `common` | **Protocol** | Wire protocol (`Message` enum), `Command` vocabulary, crypto primitives (`CryptoSession`), TLS transport, error types, audit types, configuration structs |
| `agent` | **Endpoint** | Resident service on managed endpoints — receives authenticated commands, executes them within policy constraints, reports results |
| `console` | **Operator CLI** | Signs/encrypts requests, dispatches to agents, renders results (legacy protocol-test CLI) |
| `orchestra-server` | **Control Center** | HTTPS dashboard + agent listener — `axum` REST/WebSocket frontend, TLS + AES-GCM agent channel, JSONL audit log |
| `builder` | **Build tool** | Profile-driven CLI builder — generates outbound profiles, compiles agent payloads, encrypts output |
| `launcher` | **Bootstrap stub** | Downloads encrypted payload over HTTPS, decrypts in memory, executes without touching disk |
| `optimizer` | **Performance** | Detects host CPU microarchitecture and applies optimized implementations via runtime dispatch |
| `module_loader` | **Plugins** | Fetches signed capability plugins, verifies SHA-256 + signature chain, loads in memory |
| `hollowing` | **Process ops** | Cross-platform process hollowing primitive (Windows primary, stub elsewhere) |
| `payload-packager` | **Packaging** | AES-256-GCM encrypted bundle producer for launcher consumption |
| `dev-server` | **Development** | Static-file HTTP server for local QA (no auth, localhost only) |
| `string_crypt` | **Obfuscation** | Compile-time string encryption proc-macro |
| `code_transform` | **Obfuscation** | Compile-time code transformation proc-macro |
| `code_transform_macro` | **Obfuscation** | Helper proc-macro for `code_transform` |
| `nt_syscall` | **Low-level** | Windows NT direct-syscall wrappers |
| `keygen` | **Utility** | Ed25519 keypair generation for module signing |
| `pe_resolve` | **PE ops** | PE header parsing and export resolution |

### Security boundaries

- The agent only executes **named, pre-registered scripts** — never arbitrary command strings. Enforced at the protocol layer via `Command::RunApprovedScript`.
- All console↔agent traffic is encrypted with AES-256-GCM. Development builds use a pre-shared key; production can use X25519 ephemeral key exchange for forward secrecy.
- Modules are signed and content-addressed; `module_loader` rejects unverified blobs.

---

## Communication protocol

All operator↔agent traffic is modelled as a single `Message` enum defined in `common/src/lib.rs`. The enum is `Serialize`/`Deserialize` via `bincode` (not JSON) for compact framing.

### Frame format

Each frame on the wire is:

```
┌──────────────┬─────────────────────────────────┐
│ u32 LE (4 B) │ bincode-serialised Message       │
│ length       │                                  │
└──────────────┴─────────────────────────────────┘
```

The length prefix does **not** include itself — it is the byte count of the payload that follows.

### Message variants

| Variant | Direction | Purpose |
|---------|-----------|---------|
| `VersionHandshake` | agent → server (init), server → agent (echo) | Protocol version negotiation. Current version: `2`. |
| `Heartbeat` | agent → server | Reports liveness, identity, and coarse status. |
| `TaskRequest` | server → agent | Requests execution of a `Command` under a unique `task_id`. Includes optional `operator_id`. |
| `TaskResponse` | agent → server | Returns `Ok(stdout)` or `Err(message)` keyed by `task_id`. |
| `ModulePush` | server → agent | Delivers an encrypted, signed capability module. |
| `AuditLog` | agent → server | Pushes an `AuditEvent` record for compliance logging. |
| `Shutdown` | either | Graceful session termination. |

### Command vocabulary

`Command` is a closed set — there is **no** arbitrary shell command variant. The closest is `StartShell` which opens an interactive PTY managed by the agent. All file operations are constrained by `allowed_paths`.

| Command | Purpose |
|---------|---------|
| `Ping` | Liveness check. |
| `GetSystemInfo` | Host inventory (OS, arch, uptime, memory). |
| `RunApprovedScript { script }` | Execute a pre-registered named maintenance script. |
| `ListDirectory { path }` | List files within `allowed_paths`. |
| `ReadFile { path }` | Read file contents within `allowed_paths`. |
| `WriteFile { path, content }` | Write file within `allowed_paths`. |
| `DeployModule { module_id }` | Stage a capability module from the cache. |
| `ExecutePlugin { plugin_id, args }` | Execute a loaded plugin with arguments. |
| `StartShell` | Open an interactive PTY session (returns `session_id`). |
| `ShellInput { session_id, data }` | Write bytes to a PTY session's stdin. |
| `ShellOutput { session_id }` | Poll a PTY session's stdout/stderr. |
| `CloseShell { session_id }` | Terminate a PTY session and free file descriptors. |
| `Shutdown` | Gracefully stop the agent. |
| `DiscoverNetwork` | Bounded subnet enumeration (`network-discovery` feature). |
| `CaptureScreen` | Capture primary display as PNG (`remote-assist` feature). |
| `SimulateKey { key }` | Simulate key press (`remote-assist` + consent). |
| `SimulateMouse { x, y }` | Simulate mouse movement (`remote-assist` + consent). |
| `StartHciLogging` | Begin HCI telemetry capture (`hci-research` feature). |
| `StopHciLogging` | Stop HCI telemetry capture. |
| `GetHciLogBuffer` | Drain buffered HCI events. |
| `ReloadConfig` | Re-read `agent.toml` at runtime. |
| `EnablePersistence` | Install opt-in persistence service. |
| `DisablePersistence` | Remove persistence service. |
| `MigrateAgent { target_pid }` | Migrate into another process (experimental, platform-gated). |
| `ListProcesses` | Return JSON snapshot of running processes. |

---

## Cryptography

### AES-256-GCM with HKDF-SHA256

Every framed message is encrypted with AES-256-GCM. Key derivation uses HKDF-SHA256 with a per-message random salt.

**Wire format (protocol v2):**

```
┌────────────┬──────────────┬─────────────────────────────┐
│ salt (32B) │ nonce (12B)  │ ciphertext + GCM tag (16B)  │
└────────────┴──────────────┴─────────────────────────────┘
```

- **Salt**: 32 random bytes, freshly drawn from the OS CSPRNG (`rand::thread_rng`) per message.
- **Nonce**: 12 random bytes per message.
- **Key derivation**: `HKDF-SHA256(salt, psk, info=b"orchestra-v2")` → 32-byte per-message key.
- **Authentication failure is fatal**: the receiver discards the message and logs the event.

The `CryptoSession` type wraps these operations:

| Method | Behaviour |
|--------|-----------|
| `encrypt(plaintext)` | Generates salt + nonce, derives per-message key, encrypts. Returns `salt ‖ nonce ‖ ciphertext_with_tag`. |
| `decrypt_with_psk(psk, wire_data)` | Extracts salt, derives key via HKDF, decrypts. Handles both v2 (salt-prefixed) and legacy v1 (`nonce ‖ ciphertext`) formats. |

### Forward secrecy (optional)

When the `forward-secrecy` feature is enabled, an X25519 ephemeral Diffie-Hellman exchange is performed after the TLS handshake:

1. Both sides generate a fresh `EphemeralSecret` (X25519).
2. Public keys are exchanged over the encrypted channel.
3. Both compute `X25519(priv, peer_pub)` shared secret.
4. HKDF-SHA256 mixes the shared secret with `SHA-256(PSK)` and the domain string `"orchestra-fs-v1"` to derive a 32-byte `session_key`.
5. All subsequent frames use a `CryptoSession` constructed from `session_key`.

**Guarantee**: a passive observer who later learns the PSK cannot decrypt recorded sessions because the ephemeral key material is never persisted.

---

## Transport abstraction

`Transport` is an `async_trait` with `send(Message)` and `recv() -> Message`:

```rust
#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(&mut self, msg: Message) -> Result<()>;
    async fn recv(&mut self) -> Result<Message>;
}
```

It leaves framing, congestion handling, and reconnection to concrete implementations. Available transports:

| Transport | Description |
|-----------|-------------|
| `TlsTransport<S>` | Wraps any `AsyncRead + AsyncWrite` stream with TLS + 4-byte length-prefix bincode framing |
| `TcpTransport` | Plaintext TCP with length-prefix bincode (development only) |
| Loopback | In-memory channel pair for integration tests |

The on-wire codec is **bincode** (not JSON). Each frame: `u32 LE length prefix ‖ bincode-serialised Message`.

### Outbound agent connection flow

```
agent                              orchestra-server
  │                                       │
  │──── TCP connect to agent_addr ───────►│
  │              TLS handshake            │
  │◄─────────────────────────────────────►│
  │     [optional X25519 key exchange]    │
  │◄─────────────────────────────────────►│
  │        VersionHandshake (v=2)         │
  │◄─────────────────────────────────────►│
  │           Heartbeat (register)        │
  │                                       │
  │◄─────── TaskRequest ─────────────────│  (server pushes command)
  │──────── TaskResponse ────────────────►│
  │          ... command loop ...          │
```

---

## Module loading

The `module_loader` crate provides secure dynamic extension of the agent.

### Encryption and verification

- **Encryption**: Plugins are encrypted with AES-256-GCM via `CryptoSession`.
- **Ed25519 signatures** (`module-signatures` feature, on by default): The packager signs the plaintext module with an Ed25519 private key. The 64-byte signature is prepended: `[signature][module_data]`. The loader verifies against a public key before decryption.
- **GCM tag**: Provides integrity and authenticity of the encrypted payload.

### In-memory loading

| Platform | Loading method |
|----------|---------------|
| **Linux** | `memfd_create` → write to anonymous fd → `libloading` loads from `/proc/self/fd/<fd>` — plugin never touches disk |
| **Windows** (with `manual-map`) | PE loader parses headers, copies sections, resolves imports, applies relocations, calls entry point — all in memory |
| **Other** | Temp-file fallback (less secure, compatibility mode) |

### Plugin interface

Plugins implement the `Plugin` trait:

```rust
pub trait Plugin {
    fn init(&self);
    fn execute(&self);
}
```

Exported via `_create_plugin()` extern function.

### Module-signing key policy

| Mode | Behaviour |
|------|-----------|
| `module_verify_key = Some(b64)` | Verifies against the supplied Ed25519 public key |
| `module_verify_key = None` | Falls back to compile-time constant `MODULE_SIGNING_PUBKEY` |
| `strict-module-key` feature | Converts `None` fallback into hard `Err` — use for production |

---

## Configuration

### Agent configuration (`agent.toml`)

| Field | Default | Description |
|-------|---------|-------------|
| `allowed_paths` | `/var/log`, `/home`, `/tmp` | File-system subtrees the agent can read/write |
| `heartbeat_interval_secs` | `30` | Interval between liveness heartbeats |
| `persistence_enabled` | `false` | Opt-in: install systemd/scheduled-task entry |
| `module_repo_url` | — | Base URL for fetching capability modules |
| `module_signing_key` | `None` | Base64 AES-256 key for module decryption |
| `module_cache_dir` | Platform-specific | Directory for pre-staged module blobs |

The agent reads `~/.config/orchestra/agent.toml` at startup (or creates a safe default). `ReloadConfig` re-reads at runtime.

### Build profiles (`profiles/<name>.toml`)

| Field | Required | Description |
|-------|----------|-------------|
| `target_os` | yes | `linux`, `windows`, or `macos` |
| `target_arch` | yes | `x86_64`, `aarch64`, etc. |
| `c2_address` | yes | `host:port` the agent dials |
| `encryption_key` | yes | AES-256 key for payload encryption |
| `c_server_secret` | yes | PSK matching server's `agent_shared_secret` |
| `server_cert_fingerprint` | no | SHA-256 DER fingerprint for cert pinning |
| `features` | no | Cargo features to compile into the agent |
| `package` | yes | Must be `"agent"` |
| `bin_name` | no | Binary name (default: `agent-standalone`) |

### Path validation

All filesystem I/O routes through `fsops::validate_path`:

1. **Fast-path `..` rejection** — any `..` component is rejected before filesystem I/O.
2. **Canonicalization** — resolves symlinks and produces absolute path.
3. **Allow-list check** — canonical path must be under one of `config.allowed_paths`.
4. **TOCTOU protection** — `write_file` opens with `O_NOFOLLOW` on Unix to prevent final-component symlink swap.

---

## Audit logging

Every command generates an `AuditEvent`:

| Field | Description |
|-------|-------------|
| `timestamp` | Unix seconds |
| `agent_id` | Endpoint hostname |
| `user` | Operator identity (from `operator_id` in `TaskRequest`) |
| `action` | Human-readable command description (sensitive fields redacted) |
| `details` | Success message or error string |
| `outcome` | `Success` or `Failure` |

**Tamper-evidence**: Each audit record is signed with HMAC-SHA256. The HMAC key is derived from the admin token. Tampered entries are flagged on read.

**Sensitive data hygiene**: `sanitize_result` strips file contents, shell I/O, and screenshot data from audit records — replaced with size summaries.

---

## Performance

Benchmarks from `agent/benches/agent_benchmark.rs` (Criterion):

| Metric | Result |
|--------|--------|
| Ping encode + encrypt | ~3 µs |
| AES-256-GCM throughput (100 MiB) | >3 GiB/s (AES-NI accelerated) |
| Soak test RSS growth | <1 MiB over 1M iterations |

Run benchmarks:

```sh
cargo bench -p agent --bench agent_benchmark
```

Long-running stability:

```sh
ORCHESTRA_SOAK_HOURS=1 cargo test --release --test soak_test
```

---

## Cross-platform support

| OS | Default tests | Optional checks |
|----|---------------|-----------------|
| Linux (ubuntu-latest) | Full | Feature-module compile, doc/feature drift, deterministic proc-macro |
| Windows (windows-latest) | Compile | Windows-facing agent features, `module_loader/manual-map` |
| macOS (macos-latest) | Compile | macOS agent features when Darwin toolchain present |

Platform-specific code is gated with `#[cfg(target_os = "...")]` attributes so `cargo check --workspace` succeeds on all platforms without warnings.

---

## See also

- [QUICKSTART.md](QUICKSTART.md) — Clone to first command in 8 steps
- [CONTROL_CENTER.md](CONTROL_CENTER.md) — Server configuration and REST API
- [FEATURES.md](FEATURES.md) — Complete feature flag reference
- [SECURITY.md](SECURITY.md) — Threat model and hardening guide
