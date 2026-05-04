# Security

This document covers Orchestra's security design and provides guidance for
both **operators** deploying the system and **auditors** reviewing the codebase.

---

## Table of contents

- [Threat Model](#threat-model)
- [Operator Hardening Checklist](#operator-hardening-checklist)
- [TLS Configuration](#tls-configuration)
- [Key Management and Rotation](#key-management-and-rotation)
- [Audit Trail](#audit-trail)
- [For Auditors](#for-auditors)
  - [Unsafe Block Inventory](#unsafe-block-inventory)
  - [Path-Traversal Review](#path-traversal-review)
  - [Dependency Audit Methodology](#dependency-audit-methodology)
  - [Sensitive Data Hygiene](#sensitive-data-hygiene)
  - [Module-Signing Key Policy](#module-signing-key-policy)
- [Security Fixes Applied](#security-fixes-applied)
- [Outstanding Follow-ups](#outstanding-follow-ups)

---

## Threat Model

Orchestra is operated **by an authorized administrator** against endpoints
they own or are explicitly authorized to manage. The threat model focuses on:

| Threat | Mitigation |
|--------|------------|
| Network attacker between console and agent | TLS encryption; optional mTLS for agent channel |
| Compromised module repository | AES-GCM authenticated encryption + Ed25519 signature verification |
| Local non-root user abusing agent IPC | Pre-shared key / mTLS client certificate |
| Path traversal via crafted file arguments | `validate_path` with canonicalization + `allowed_paths` allow-list + `O_NOFOLLOW` |
| PSK compromise leading to session decryption | Optional X25519 forward secrecy (`forward-secrecy` feature) |
| Audit log tampering | HMAC-SHA256 signed entries; tampered records flagged on read |
| Rogue agent impersonating another | Server-assigned `connection_id` as primary registry key |

**Out of scope**: defending against a fully privileged local attacker on the
agent host.

---

## Operator Hardening Checklist

Use this checklist when deploying Orchestra to production.

### TLS and certificates

- [ ] Replace self-signed TLS certificates with real certificates from a trusted CA
- [ ] Set `tls_cert_path` and `tls_key_path` in `orchestra-server.toml`
- [ ] Pin server certificate fingerprint in agent profiles via `server_cert_fingerprint`
- [ ] Consider enabling mTLS for the agent channel: `mtls_enabled = true`
- [ ] Use `./scripts/generate-certs.sh` only for testing, never production

### Authentication

- [ ] Generate strong `admin_token` — at least 32 bytes of entropy
- [ ] Generate strong `agent_shared_secret` — at least 32 bytes of entropy
- [ ] Never commit credentials to version control
- [ ] Replace bearer token auth with mTLS or SSO reverse proxy for operator access
- [ ] Enable `strict-module-key` feature for production agent builds

### Network

- [ ] Bind `http_addr` to `127.0.0.1` if using a reverse proxy
- [ ] Restrict `agent_addr` access to known agent source networks via firewall
- [ ] Place the server behind an SSO-aware reverse proxy for enterprise deployments
- [ ] Pin the dashboard CSP if customising `static/index.html`

### Audit

- [ ] Set `audit_log_path` to a dedicated, append-only directory
- [ ] Forward the JSONL audit log to your SIEM
- [ ] Periodically verify HMAC integrity of audit records
- [ ] Review `operator_id` entries to verify all actions are attributed

### Agent builds

- [ ] Use `forward-secrecy` feature for production agents
- [ ] Enable `env-validation` on sensitive deployments
- [ ] Set `persistence_enabled = false` unless explicitly needed
- [ ] Minimize enabled features to reduce attack surface

### Build queue

- [ ] Set `build_retention_days` to clean up old artifacts
- [ ] Restrict `builds_output_dir` permissions
- [ ] Limit `max_concurrent_builds` to prevent resource exhaustion

---

## TLS Configuration

### Generating production certificates

```sh
# Certificate Authority
openssl req -x509 -newkey ed25519 -keyout ca.key -out ca.pem -days 365 \
    -nodes -subj "/CN=OrchestraCA"

# Server certificate
openssl req -newkey ed25519 -keyout server.key -out server.csr -nodes \
    -subj "/CN=orchestra.example.com"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out server.pem -days 365 \
    -extfile <(echo "subjectAltName=DNS:orchestra.example.com,IP:10.0.0.5")

# Get SHA-256 fingerprint for agent pinning
openssl x509 -in server.pem -outform DER | sha256sum | awk '{print $1}'
```

### Server configuration

```toml
tls_cert_path = "/etc/orchestra/server.pem"
tls_key_path  = "/etc/orchestra/server.key"
```

### mTLS for agent channel

```toml
mtls_enabled       = true
mtls_ca_cert_path  = "/etc/orchestra/ca.pem"
mtls_allowed_cns   = ["agent.example.com"]
mtls_allowed_ous   = ["OrchestraAgents"]
```

### Self-signed certificates (testing only)

```sh
./scripts/generate-certs.sh
# Generates server.pem + server.key with SANs for localhost and LAN IPs
# Prints SHA-256 fingerprint for profile pinning
```

> **Warning**: Self-signed certificates are acceptable only for local
> development and testing. Never use them in production.

---

## Key Management and Rotation

### Credential types

| Credential | Purpose | Storage |
|------------|---------|---------|
| `admin_token` | Dashboard + API authentication | `orchestra-server.toml` |
| `agent_shared_secret` | Agent PSK for AES-GCM session | `orchestra-server.toml` + agent profile |
| `encryption_key` | Payload encryption at rest | Agent profile |
| `c_server_secret` | Agent-to-server PSK | Agent profile (baked into binary) |
| Module signing key | Ed25519 keypair for plugin verification | Generated via `keygen` utility |

### Rotation procedure

1. **Generate new credentials:**
   ```sh
   NEW_TOKEN=$(openssl rand -hex 32)
   NEW_SECRET=$(openssl rand -hex 32)
   ```

2. **Update server config** with new `admin_token` and `agent_shared_secret`.

3. **Rebuild agent profiles** with new `c_server_secret` matching the new
   `agent_shared_secret`.

4. **Redeploy agents** — agents with old credentials will fail to authenticate
   and exit cleanly.

5. **Archive old audit logs** before rotation for continuity.

6. **Verify** new agents appear in the dashboard with the updated credentials.

### Forward secrecy

Enable `forward-secrecy` in agent profiles so that PSK compromise does not
compromise recorded sessions:

```toml
features = ["outbound-c", "forward-secrecy"]
```

---

## Audit Trail

### Format

Audit events are stored as JSONL (one JSON object per line) with paired
HMAC-SHA256 tags:

```
{"timestamp":1234567890,"agent_id":"host1","user":"admin","action":"Ping","details":"ok","outcome":"Success"}
hmac-sha256-tag-here
{"timestamp":1234567891,"agent_id":"host1","user":"admin","action":"ReadFile","details":"[file content redacted, 1024 base64 bytes]","outcome":"Success"}
hmac-sha256-tag-here
```

### Tamper detection

- Each JSON entry is signed with HMAC-SHA256 keyed with a key derived from
  the admin token.
- `AuditLog::read_entries()` verifies the tag and flags tampered records.
- Tampered entries are included in results with a `tampered: true` flag.

### Sensitive data redaction

`sanitize_result()` strips sensitive data before audit logging:

| Data type | Recorded in audit |
|-----------|-------------------|
| File contents | `[file content redacted, N base64 bytes]` |
| Shell I/O | `[shell output redacted, N bytes]` |
| Screenshot data | Size summary only |

### Integration with SIEM

The JSONL format is designed for easy integration:

```sh
# Tail and forward to SIEM
tail -F /var/log/orchestra/audit.jsonl | your-siem-shipper
```

---

## For Auditors

This section provides the full audit trail for security reviewers.

### Unsafe block inventory

Every `unsafe` block carries an inline `// SAFETY:` comment.

| File | `unsafe` use | Justification |
|------|-------------|---------------|
| `module_loader/src/lib.rs` | `libc::memfd_create` | Linux-only syscall wrapper. Valid `CString`, documented constant. |
| `module_loader/src/lib.rs` | `File::from_raw_fd(fd)` | Freshly-created descriptor we own. |
| `module_loader/src/lib.rs` | `Library::new(path)` | Loading shared library — blob has been GCM-authenticated. |
| `module_loader/src/lib.rs` | `library.get(b"_create_plugin")` | Symbol type matches plugin-side signature. |
| `module_loader/src/lib.rs` | `Box::from_raw(plugin_ptr)` | Pointer returned by `Box::into_raw` on plugin side. |
| `optimizer/src/lib.rs` | `mprotect` + raw instruction patch | Page restored to read+exec after patch; transformation verified with test vectors. |
| `plugins/hello_plugin/src/lib.rs` | `extern "C"` plugin entry | Symmetric with loader expectations. |
| `agent/src/memory_guard.rs` | Raw pointer extraction for `KeyBufPtr` | Pointer from valid `&'static mut [u8; 32]` before borrow consumed; only accessed while holding `Mutex` guard. |
| `agent/src/syscalls.rs` | `do_syscall` inline asm (x86_64 + aarch64) | Register bindings explicitly constrained; aarch64 >6-arg calls fail with `EINVAL`. |
| `agent/src/syscalls.rs` | `spoof_call` register pivot | Preserves call ABI; validates prerequisites before transfer. |
| `agent/src/stack_db.rs` | PE export table walking, `RtlLookupFunctionEntry` | Null-terminated byte hashes; VirtualQuery validation before address reuse; Mutex-guarded database rebuilds. |
| `agent/src/stack_db.rs` | Raw pointer reads for `ret` gadget scanning | Bounded scan (128 bytes) within committed executable memory; unwind metadata verified before use. |
| `agent/src/evasion.rs` | VEH handler ret-gadget / jump-chain | Bounded search with page-boundary checks; capped depth; validated encodings only. |

### Path-traversal review

All filesystem I/O routes through `agent::fsops::validate_path`:

1. **`..` rejection** — any `..` component rejected before filesystem I/O.
2. **Canonicalization** — `Path::canonicalize` resolves symlinks to absolute paths.
3. **Allow-list check** — canonical path must be under one of `config.allowed_paths`.
4. **TOCTOU protection** — `write_file` opens with `O_NOFOLLOW` on Unix to prevent
   final-component symlink swap between validation and write.
5. **Non-Unix fallback** — post-write `symlink_metadata` check on other platforms.

**Test coverage:**
- `validate_path_accepts_file_inside_allowed_dir`
- `validate_path_rejects_parent_dir_traversal`
- `validate_path_rejects_symlink_outside_allowed`
- `validate_path_allows_nonexistent_file_in_allowed_dir`
- `validate_path_rejects_when_no_roots_configured`
- `write_file_refuses_final_component_symlink` (Linux)

**Module deployment hardening:**
- `module_id` validated against `^[A-Za-z0-9_-]{1,128}$`
- Module path built from `config.module_cache_dir` only
- `fsops::read_file` applies allow-list validation
- Operators must include `module_cache_dir` in `allowed_paths`

### Dependency audit methodology

Run on every push via CI (`.github/workflows/ci.yml` job `audit`):

```sh
cargo audit
```

Results: **No vulnerable dependencies** detected against the latest RustSec
advisory database.

If a future advisory affects a transitive crate:

```sh
cargo update -p <crate>
cargo test --workspace
```

### Sensitive data hygiene

**Hard-coded secrets search:**

```sh
grep -RIn -E "(password|secret|api[_-]?key|BEGIN PRIVATE KEY)" -- .
```

Results:
- Documentation strings only (this file, DESIGN.md)
- `"benchmark-shared-secret"` in `agent/benches/agent_benchmark.rs` (micro-benchmark seed only)

**No production binary** contains embedded private keys, certificates, or
shared secrets. All credentials supplied at runtime.

**Audit log redaction:**

`sanitize_result()` in `agent/src/handlers.rs` strips:
- File contents → size summary
- Shell I/O → size summary
- Screenshot data → size summary

Verified by tests:
- `audit_event_does_not_contain_file_contents`
- `shell_io_is_redacted_in_audit`

### Module-signing key policy

When `module-signatures` is enabled:

| Mode | Behaviour | Recommendation |
|------|-----------|----------------|
| Runtime key provided (`module_verify_key = Some(b64)`) | Verifies against supplied Ed25519 public key | **Production** |
| No runtime key (`module_verify_key = None`) | Falls back to compile-time `MODULE_SIGNING_PUBKEY` | Testing only |
| `strict-module-key` feature enabled | Hard error if no runtime key | **Production** |

CI tests both paths:
- `--features module-signatures` (fallback allowed)
- `--features strict-module-key` (fallback rejected)

Generate signing keypairs:

```sh
cargo run --bin keygen -- --module-signing-key
```

---

## Security Fixes Applied

The following issues were identified and resolved during the security audit:

| # | Issue | Fix | Severity |
|---|-------|-----|----------|
| 1 | `memfd_create` passed `&str` as `*const c_char` | Use `CString::new()` for valid nul-terminated ptr | Medium |
| 2 | `_create_plugin` FFI-safety warning masking others | Documented `#[allow(improper_ctypes_definitions)]` | Low |
| 3 | `module_loader` failed on non-Linux | Gated `use std::os::unix::io` behind `#[cfg(target_os = "linux")]` | Medium |
| 4 | Test referenced unimported `fs::create_dir` | Switched to fully-qualified `std::fs::create_dir` | Low |
| 5 | `memory_guard` E0499 borrow error with `stealth,memory-guard` | Extract raw pointer before calling `register()` | High |
| 6 | `forward-secrecy` compile failure in `agent_link` | Added `mut` to `tls_stream` binding | Medium |
| 7 | Builder allowed `package = "launcher"` (circular dependency) | Returns descriptive `bail!` error | High |
| 8 | Raw file contents in audit events | `sanitize_result()` replaces with size summaries | Medium |
| 9 | TOCTOU symlink swap in `write_file` | Opens with `O_NOFOLLOW` on Unix | Medium |
| 10 | Build handler accepted arbitrary `output_dir` | Validates subdirectory of configured build dir | High |
| 11 | Persistence status codes silently ignored | Each OS step now checks return codes | Medium |
| 12 | Direct-syscall ABI edge cases | Tightened x64 constraints; aarch64 >6-arg returns `EINVAL` | High |
| 13 | Manual-map assumed shared ASLR bases | Added remote module enumeration + export resolution | High |
| 14 | PE32/WOW64 hollowing gaps | Added PE32 path with WOW64 context + HIGHLOW relocations | Medium |
| 15 | VEH hook-chain traversal too permissive | Bounded depth, guarded ret-gadget search | High |
| 16 | macOS persistence shell pipeline weaknesses | Replaced with safe subprocess I/O | Medium |
| 17 | macOS IMDS lacked IMDSv2 awareness | Added IMDSv2 token flow with bounded timeout | Medium |
| 18 | Transport modules missing feature gates | Added explicit module-level feature gating | Low |
| 19 | `memory_guard_stub` under-documented | Added no-op docs, warning, parity entry points | Low |
| 20 | Windows/macOS CI validation gaps | Added cross-platform compile verification jobs | Medium |
| 21 | macOS mouse detection via Python | Replaced with native CoreGraphics path | Medium |
| 22 | Linux desktop-window fallback silent undercount | Added permission probe, sentinel, neutral scoring | Medium |
| 23 | IMDS aggressive timeout false negatives | Increased timeout, added retry, 1s budget | Medium |
| 24 | VM-refusal bypass required exact IMDS match | Added fallback controls | Medium |
| 25 | VM threshold lacked operator extension | Added `vm_detection_extra_hypervisor_names` | Medium |
| 26 | Optimizer helper dead-code lint noise | Matched cfg to diversification pass | Low |

---

## New Feature Security Considerations

The following sections cover security considerations for features added since
the initial security audit.

### LSASS Credential Harvesting (`HarvestLSASS`)

**Risk level: HIGH**

| Concern | Mitigation |
|---------|------------|
| LSASS requires `SE_DEBUG_NAME` privilege | Agent validates privilege before attempting access |
| EDR heavily monitors LSASS process handles | Uses `NtOpenProcess` with `PROCESS_VM_READ` only (not `PROCESS_ALL_ACCESS`) |
| Credential material in memory | Credentials are encrypted in transit (AES-256-GCM CryptoSession) and never written to disk |
| Audit trail | Operation is always logged with operator identity and timestamp |
| Post-harvest cleanup | LSASS handle is closed immediately; credential buffers are zeroed with `SecureZeroMemory` |

**Operator guidance:**
- Use `StealToken` from a SYSTEM process to obtain `SE_DEBUG_NAME` before running `HarvestLSASS`
- Rotate harvested credentials immediately — do not store in the audit log
- Consider OPSEC implications: LSASS access is one of the most heavily monitored operations

### Browser Data Extraction (`BrowserData`)

**Risk level: MEDIUM**

| Concern | Mitigation |
|---------|------------|
| Chrome v127+ App-Bound Encryption | Agent implements the IElevator COM interface to decrypt cookies |
| Database file locking | Uses shadow copies (`CopyFileEx`) rather than opening live DB files |
| Credential material in memory | All extracted data is encrypted via CryptoSession before transmission |
| Anti-tamper detection by browsers | Agent operates on copies, never modifies original DB files |

**Supported browsers:** Chrome, Edge, Firefox, Brave (cookie and credential extraction)

### Surveillance Module (`surveillance` feature)

**Risk level: MEDIUM**

| Concern | Mitigation |
|---------|------------|
| Keystroke data sensitivity | Encrypted ring buffer with XChaCha20-Poly1305; keys held in guarded memory |
| Screenshot data volume | Compressed via `image` crate (PNG); configurable resolution and interval |
| Clipboard content exposure | Clipboard snapshots are encrypted in transit; redacted in audit log |
| Detection by monitoring tools | Uses `GetAsyncKeyState` polling (not hooks); screenshots via native Win32 API |

**Feature flags:**
- `surveillance` enables: `Screenshot`, `KeyloggerStart`, `KeyloggerStop`, `KeyloggerDump`, `ClipboardGet`, `ClipboardSet`
- Requires `dep:image` for screenshot encoding

### NTDLL Unhooking (`UnhookNtdll`)

**Risk level: LOW (defensive)**

| Concern | Mitigation |
|---------|------------|
| `\KnownDlls` access monitored by EDR | Fallback to on-disk `C:\Windows\System32\ntdll.dll` |
| Hook detection false positives | Only checks first 5 bytes of syscall stubs for well-known hook patterns |
| `.text` section re-fetch overhead | Lazy — only performed when hooks are actually detected |
| Post-sleep re-hooking | Step 12 of sleep cycle performs automatic `maybe_unhook()` after each wake |

### Interactive Shell Sessions

**Risk level: MEDIUM**

| Concern | Mitigation |
|---------|------------|
| PTY allocation detection | Uses standard `CreatePseudoConsole` (Windows) / `forkpty` (Unix) |
| Shell history persistence | Agent sets `HISTFILE=/dev/null` and `history -c` on session start |
| Multiple concurrent sessions | Bounded by `MAX_SHELL_SESSIONS` (default: 5); excess requests return error |
| Session cleanup | All PTY handles and child processes are cleaned up on session close or agent shutdown |

### Token Manipulation

**Risk level: HIGH**

| Concern | Mitigation |
|---------|------------|
| Privilege escalation audit trail | All token operations (`MakeToken`, `StealToken`, `Rev2Self`, `GetSystem`) are logged |
| Token handle leaks | RAII `HandleGuard` ensures all token handles are closed |
| `Rev2Self` without prior `MakeToken` | Agent tracks original token; `Rev2Self` is a no-op if no token was stored |
| `GetSystem` via named pipe impersonation | Creates a temporary service binary; cleans up service and binary after use |

### .NET Assembly and BOF Execution

**Risk level: MEDIUM**

| Concern | Mitigation |
|---------|------------|
| CLR loading detection | Uses `ICLRMetaHost` → `ICLRRuntimeHost` (legitimate hosting API) |
| BOF memory leaks | COFF loader tracks all allocations; frees on completion or timeout |
| Assembly timeout | Configurable wall-clock timeout (default: 30s); CLR thread is terminated on expiry |
| AMSI bypass | `write-raid-amsi` (data-only race, preferred) or `hwbp-amsi` (DR0/DR1 VEH) or memory-patch (fallback) |

---

## Outstanding Follow-ups

Tracked in `ROADMAP.md`:

| Item | Priority | Status |
|------|----------|--------|
| HMAC-SHA256 audit event signatures | — | **Completed** |
| X25519 forward secrecy | — | **Completed** (opt-in via `forward-secrecy` feature) |
| Sandboxed plugin execution (seccomp / Job Objects) | Medium | Pending |
| Remote manual-map import resolution regression coverage | High | In progress |
| PE32 process-hollowing hardening | Medium | Pending |
| Windows/macOS CI quality gates | High | In progress |
| macOS native mouse-detection hardening | Medium | Pending |
| OIDC/SSO for operator login | Medium | Planned |

---

## See also

- [ARCHITECTURE.md](ARCHITECTURE.md) — Wire protocol and crypto details
- [CONTROL_CENTER.md](CONTROL_CENTER.md) — Server configuration and REST API
- [FEATURES.md](FEATURES.md) — Complete feature flag reference
- [QUICKSTART.md](QUICKSTART.md) — Getting started guide
