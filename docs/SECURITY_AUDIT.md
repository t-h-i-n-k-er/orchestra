# Orchestra Security Audit

**Audit date:** 2026-04-21
**Audit scope:** Entire workspace at the tagged release.
**Auditor:** Project maintainer self-review (pre-public-release).

This document records the methodology and findings of an internal security
review performed in preparation for the first public release of Orchestra.

---

## 1. Methodology

| Step | Tool / Technique                                     | Outcome           |
|------|------------------------------------------------------|-------------------|
| 1    | `cargo audit` against RustSec advisory DB            | See §3            |
| 2    | `cargo clippy --workspace -- -D warnings`            | Clean (§4)        |
| 3    | Manual review of every `unsafe` block                | See §5            |
| 4    | Path-traversal review of every filesystem operation  | See §6            |
| 5    | Search for hard-coded secrets / keys                 | None found (§7)   |
| 6    | Re-run unit tests + benchmarks after each change     | All green         |

---

## 2. Threat model summary

Orchestra is operated **by an authorized administrator** against endpoints
they own or are explicitly authorized to manage. The threat model therefore
focuses on:

- A network attacker between the console and the agent (mitigated by mTLS).
- A compromised module repository pushing a malicious plugin (mitigated by
  AES-GCM authenticated encryption + signed-blob verification).
- A local non-root user attempting to abuse the agent's IPC endpoint
  (mitigated by the pre-shared key / mTLS client certificate).
- Path traversal via crafted file-operation arguments (mitigated by
  `validate_path` and the `allowed_paths` allow-list).

Out of scope: defending against a fully privileged local attacker on the
agent host.

---

## 3. Dependency audit (`cargo audit`)

Run on 2026-04-21 against the latest RustSec advisory database. **No
vulnerable dependencies** were detected. CI re-runs `cargo audit` on every
push (see `.github/workflows/ci.yml` job `audit`).

If a future advisory affects a transitive crate, regenerate `Cargo.lock`
with `cargo update -p <crate>` and re-test.

---

## 4. Clippy / lint review

`cargo clippy --workspace -- -D warnings` exits 0. The single
intentionally-allowed lint is in `plugins/hello_plugin/src/lib.rs`:

```rust
#[allow(improper_ctypes_definitions)]
pub extern "C" fn _create_plugin() -> *mut dyn Plugin
```

This is required by the plugin loader's calling convention and is safe
because both sides are compiled by the same `rustc` toolchain.

---

## 5. `unsafe` block review

| File                                 | `unsafe` use                                   | Justification                                                                                     |
|--------------------------------------|-----------------------------------------------|---------------------------------------------------------------------------------------------------|
| `module_loader/src/lib.rs`           | `libc::memfd_create`                           | Linux-only syscall wrapper. `name` is a valid `CString`, `MFD_CLOEXEC` is a documented constant. |
| `module_loader/src/lib.rs`           | `File::from_raw_fd(fd)`                        | `fd` is a freshly-created descriptor we own.                                                     |
| `module_loader/src/lib.rs`           | `Library::new(path)`                           | Loading a shared library inherently requires `unsafe`; the blob has been GCM-authenticated.       |
| `module_loader/src/lib.rs`           | `library.get(b"_create_plugin")`               | Symbol type matches the plugin-side signature.                                                   |
| `module_loader/src/lib.rs`           | `Box::from_raw(plugin_ptr)`                    | Pointer was returned by `Box::into_raw` on the plugin side.                                      |
| `optimizer/src/lib.rs`               | `mprotect` + raw instruction patch             | Page is restored to read+exec after patch; transformation is semantically equivalent (`add` → `lea`). Safety comments inline. |
| `plugins/hello_plugin/src/lib.rs`    | `extern "C"` plugin entry                       | Symmetric with the loader's expectations.                                                         |

Each `unsafe` block carries an inline `// SAFETY:` comment explaining why
the invariants are met.

---

## 6. Path-traversal review

All filesystem I/O routes through `agent::fsops::validate_path`:

1. The path is canonicalized with `Path::canonicalize`.
2. The canonical path must be a prefix of one of the entries in
   `Config::allowed_paths`.
3. Any `..` segment in the input is rejected before canonicalization.
4. Symlinks resolve to their target; the target must also satisfy the
   allow-list test.

Unit tests in `agent::fsops::tests::path_validation_*` cover both allowed
and disallowed cases.

---

## 7. Hard-coded secrets

`grep -RIn -E "(password|secret|api[_-]?key|BEGIN PRIVATE KEY)" --` over
the source tree returned only:

- Documentation strings in `USER_GUIDE.md` and `DESIGN.md`.
- The string `"benchmark-shared-secret"` inside `agent/benches/agent_benchmark.rs`,
  used solely to seed `CryptoSession` in micro-benchmarks.

No production binary contains an embedded private key, certificate, or
shared secret. All credentials must be supplied at runtime via:

- Console: `--key <BASE64>` or `--client-cert` / `--client-key` files.
- Agent: certificates referenced from `agent.toml`, never hard-coded.

---

## 8. Sensitive-data hygiene in audit logs

`agent::handlers::sanitize_action` strips file contents and shell I/O from
the `AuditEvent::action` and `details` fields before they are serialized.
Tests:
`agent::handlers::tests::audit_event_does_not_contain_file_contents` and
`shell_io_is_redacted`.

---

## 9. Fixes applied during this audit

| # | Issue                                                                 | Fix                                                                           |
|---|----------------------------------------------------------------------|-------------------------------------------------------------------------------|
| 1 | `module_loader::memfd_create` passed an `&str` as `*const c_char`.    | Use `CString::new("orchestra_plugin")` to obtain a valid nul-terminated ptr.  |
| 2 | `_create_plugin` triggered an FFI-safety warning that masked others.  | Added a documented `#[allow(improper_ctypes_definitions)]`.                   |
| 3 | `module_loader` failed to compile on non-Linux due to unconditional `use std::os::unix::io`. | Gated the import behind `#[cfg(target_os = "linux")]`.                        |
| 4 | `agent/src/fsops.rs` test referenced an unimported `fs::create_dir`. | Switched to fully-qualified `std::fs::create_dir`.                            |

---

## 10. Outstanding follow-ups (tracked in `ROADMAP.md`)

- HMAC-SHA256 signature on each `AuditEvent` (tamper-evidence).
- Replace the pre-shared-key dev path with X25519 + HKDF authenticated
  key exchange.
- Sandboxed plugin execution (seccomp on Linux, Job Objects on Windows).
