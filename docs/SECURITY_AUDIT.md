# Orchestra Security Audit

**Audit date:** 2026-04-21 (updated 2026-05-01)
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

Run on 2026-05-01 against the latest RustSec advisory database. **No
vulnerable dependencies** were detected. CI re-runs `cargo audit` on every
push (see `.github/workflows/ci.yml` job `audit`).

If a future advisory affects a transitive crate, regenerate `Cargo.lock`
with `cargo update -p <crate>` and re-test.

---

## 4. Clippy / lint review

`cargo clippy --workspace -- -D warnings` exits 0 for default Linux
features. Windows-only crates (`winreg`, `winapi`) require the corresponding
native toolchain; clippy warnings on those paths are validated only on the
`windows-msvc-native` CI job. The single intentionally-allowed lint is in
`plugins/hello_plugin/src/lib.rs`:

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
| `agent/src/memory_guard.rs`          | Raw pointer extraction for `KeyBufPtr`          | Pointer is extracted from a valid `&'static mut [u8; 32]` before the borrow is consumed; `KeyBufPtr` is only accessed while holding the `Mutex` guard. See inline `// SAFETY:` comment. |

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
5. **TOCTOU / final-component symlink swap** — after validation, `write_file`
   opens the target with `O_NOFOLLOW` on Unix.  If a symlink is planted at
   the final path component between `validate_path` and the open, the kernel
   returns `ELOOP`/`ENOTDIR` and the write is refused.  On non-Unix targets,
   a post-write `symlink_metadata` check is performed instead.

Unit tests covering allowed and disallowed cases, including final-component
symlink swap scenarios:
- `agent::fsops::tests::validate_path_accepts_file_inside_allowed_dir`
- `agent::fsops::tests::validate_path_rejects_parent_dir_traversal`
- `agent::fsops::tests::validate_path_rejects_symlink_outside_allowed`
- `agent::fsops::tests::validate_path_allows_nonexistent_file_in_allowed_dir`
- `agent::fsops::tests::validate_path_rejects_when_no_roots_configured`
- `agent::fsops::tests::write_file_refuses_final_component_symlink` (Linux)

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

**Module-signing key** — when the `module-signatures` feature is enabled,
`module_loader` accepts an optional `module_verify_key` at runtime.  If
`module_verify_key` is `None`, the crate falls back to the compile-time
constant `MODULE_SIGNING_PUBKEY`.  See §11 for the decision and test
coverage.

---

## 8. Sensitive-data hygiene in audit logs

`agent::handlers::sanitize_result` strips file contents, shell I/O, and
screenshot data from the `AuditEvent::details` field before they are
serialized.  Sensitive results are replaced with a size summary, for
example `[file content redacted, 1024 base64 bytes]`.

Tests verifying this behaviour (both in `agent::handlers::tests`):
- `audit_event_does_not_contain_file_contents`
- `shell_io_is_redacted_in_audit`

---

## 9. Fixes applied during this audit

| # | Issue                                                                                   | Fix                                                                                                   |
|---|----------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| 1 | `module_loader::memfd_create` passed an `&str` as `*const c_char`.                     | Use `CString::new("orchestra_plugin")` to obtain a valid nul-terminated ptr.                          |
| 2 | `_create_plugin` triggered an FFI-safety warning that masked others.                    | Added a documented `#[allow(improper_ctypes_definitions)]`.                                           |
| 3 | `module_loader` failed to compile on non-Linux due to unconditional `use std::os::unix::io`. | Gated the import behind `#[cfg(target_os = "linux")]`.                                           |
| 4 | `agent/src/fsops.rs` test referenced an unimported `fs::create_dir`.                   | Switched to fully-qualified `std::fs::create_dir`.                                                   |
| 5 | `agent/src/memory_guard.rs` failed to compile with `--features stealth,memory-guard` (E0499 borrow error). | Extracted raw pointer before calling `register()`. `static KEY_BUF` now stores `Mutex<KeyBufPtr>`. |
| 6 | `orchestra-server/src/agent_link.rs` failed to compile with `--features forward-secrecy` (`negotiate_session_key` required `&mut` receiver). | Added `mut` to the `tls_stream` binding.                                                             |
| 7 | `builder` allowed `package = "launcher"` as a downloadable payload target, which creates a circular dependency (launcher downloading launcher). | `features_for_package("launcher", ...)` now returns a descriptive `bail!` error. `scripts/setup.sh` and `README.md` updated. |
| 8 | `agent::handlers` wrote raw file contents and shell output into `AuditEvent::details`. | Added `sanitize_result()` which replaces sensitive payloads with size-only summaries.                 |
| 9 | `agent::fsops::write_file` had a TOCTOU window between `validate_path` and the write where a symlink could be planted at the final path component. | `write_file` now opens the file with `O_NOFOLLOW` on Unix.                                           |
| 10 | `orchestra-server::build_handler::execute_build_safely` accepted any absolute path as `output_dir`, allowing artifact exfiltration to arbitrary filesystem locations. | `output_dir` is now validated to be a subdirectory of the configured build directory.                  |
| 11 | Persistence mechanism status codes (`RegSetValueExW`, PowerShell exit, `launchctl`, `systemctl`) were silently ignored. | Each OS registration step now checks the return code and propagates errors.                           |

---

## 10. Outstanding follow-ups (tracked in `ROADMAP.md`)

- HMAC-SHA256 signature on each `AuditEvent` (tamper-evidence).
- Replace the pre-shared-key dev path with X25519 + HKDF authenticated
  key exchange (the `forward-secrecy` feature is now compile-tested in CI;
  it is not yet the default transport).
- Sandboxed plugin execution (seccomp on Linux, Job Objects on Windows).
- `ManualMap` reflective injection (`agent/src/injection/`) is compiled
  in with `--features manual-map` but is **not functional as remote
  injection**: `module_loader::inject_into_process` is a placeholder that
  returns `Err("not implemented")`.  No remote code injection is active.

---

## 11. Module-signing key policy

When `module-signatures` is compiled in, `module_loader::load_plugin` accepts
a `module_verify_key: Option<&str>` parameter.  Current behaviour:

- **`Some(b64_key)`** — the caller supplies a base64-encoded Ed25519 public
  key; the blob signature is verified against it.
- **`None`** — the loader falls back to the compile-time constant
  `MODULE_SIGNING_PUBKEY` embedded via `string_crypt`.

The compile-time fallback exists to enable the test suite to run without
requiring a full key-management setup.  **Production deployments should
always supply an explicit `module_verify_key`** to prevent an attacker who
can modify the binary from substituting a different embedded key.

A `strict-module-key` Cargo feature has been added that converts the `None`
fallback into a hard `Err`:

```toml
# agent/Cargo.toml
[features]
strict-module-key = ["module-signatures"]
```

Enable this feature in production builds to enforce that a runtime key
is always provided.  CI tests with `--features module-signatures` (fallback
allowed) and `--features strict-module-key` (fallback rejected) are included
in `.github/workflows/ci.yml`.

