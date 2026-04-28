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
| `agent/src/syscalls.rs`              | `do_syscall` inline asm (`x86_64` + `aarch64`)  | Register bindings and clobbers are explicitly constrained; unsupported `aarch64` call shapes (>6 args) fail closed with `EINVAL` rather than undefined stack marshalling. |
| `agent/src/syscalls.rs`              | `spoof_call` register pivot and trampoline flow | Wrapper preserves call ABI expectations (`rcx`, `rdx`, `r8`, `r9`/stack) and validates gadget/trampoline prerequisites before transfer. |
| `agent/src/evasion.rs`               | VEH handler ret-gadget and jump-chain traversal | Search is bounded and guarded by page-boundary checks; hook-chain follow depth is capped and only accepted jump encodings are traversed. |

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
| 12 | Direct-syscall wrappers had ABI edge cases across architectures. | Tightened x64 inline-asm constraints and made Linux `aarch64` >6-arg calls return `EINVAL` (Prompt 1.1). **Severity: High**. |
| 13 | Remote manual-map import resolution assumed shared ASLR base addresses. | Added remote module enumeration + remote export resolution path; hard-fail if remote map cannot be built (Prompt 1.3). **Severity: High**. |
| 14 | Process hollowing lacked robust PE32/WOW64 relocation/import handling parity. | Added PE32 hollowing path with WOW64 context handling and `HIGHLOW` relocation support (Prompt 2.1). **Severity: Medium**. |
| 15 | VEH hook-chain traversal and ret-gadget discovery were too permissive. | Added bounded jump-chain following and widened/guarded ret-gadget search with safety checks (Prompt 2.2). **Severity: High**. |
| 16 | macOS persistence fallback paths relied on shell pipelines and weak status checks. | Replaced shell pipeline cron path with safe subprocess I/O and improved strategy handling (Prompt 2.3). **Severity: Medium**. |
| 17 | macOS cloud-instance identity retrieval lacked IMDSv2-aware behavior. | Added IMDSv2 token flow with fallback request path and bounded timeout behavior (Prompt 2.4). **Severity: Medium**. |
| 18 | Optional transport modules could compile without explicit feature-gate discipline. | Added explicit module-level feature gating/documentation for DoH/SSH experimental paths (Prompt 2.5). **Severity: Low**. |
| 19 | `memory_guard_stub` behavior was under-documented and API parity was incomplete. | Added explicit no-op semantics docs, one-time warning, and parity entry points (Prompt 3.1). **Severity: Low**. |
| 20 | Windows/macOS-specific code paths were under-validated in CI. | Added non-blocking cross-platform compile verification jobs and matrix documentation (Prompts 3.2/3.3). **Severity: Medium**. |
| 21 | macOS mouse-movement check depended on Python/Quartz runtime availability. | Replaced Python subprocess probe with native CoreGraphics path and warning fallback (Prompt 4.2). **Severity: Medium**. |
| 22 | Linux desktop-window fallback silently undercounted when `/proc/*/environ` permissions were restricted. | Added permission probe, explicit `EACCES` handling, unreliable-result sentinel, and neutral scoring treatment (Prompt 4.3). **Severity: Medium**. |
| 23 | IMDS probing used an overly aggressive timeout prone to cloud false negatives. | Increased connect timeout, added one retry, added elapsed-time debug diagnostics, and enforced 1s probe budget (Prompt 5.1). **Severity: Medium**. |
| 24 | VM-refusal bypass required exact IMDS instance-id match with no degraded-path controls. | Added `cloud_instance_allow_without_imds` and `cloud_instance_fallback_ids` fallback controls (Prompt 5.2). **Severity: Medium**. |
| 25 | Adaptive VM threshold edge behavior lacked operator extension controls. | Added `vm_detection_extra_hypervisor_names` and edge-case warning/documentation path (Prompt 5.3). **Severity: Medium**. |
| 26 | Optimizer helper `is_block_terminator` triggered dead-code lint noise outside feature scope. | Matched helper cfg to diversification pass usage (`#[cfg(feature = "diversification")]`) (Prompt 6.1). **Severity: Low**. |

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
- [Medium] PE32 process-hollowing compatibility hardening and broader runtime
  validation beyond current WOW64-focused coverage.
- [High] Promote Windows/macOS compile checks from non-blocking CI jobs to
  required quality gates once flake rate is reduced.
- [Medium] Continue macOS native mouse-detection hardening/coverage after
  removing Python dependency (headless and permission-edge validation).
- [High] Expand regression coverage for remote manual-map import resolution
  in mismatched-ASLR scenarios.

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

---

## 12. Payload Polymorphism Clarification

`payload-packager/src/poly.rs` implements **polymorphic payload packaging**
(structural variability in the packaged payload format/cipher layout), not
metamorphic agent self-modification.

In other words, the packager changes how payload bytes are wrapped and
encrypted across builds; it does **not** mutate the agent program semantics at
runtime.

