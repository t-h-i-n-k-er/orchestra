# Contributing to Orchestra

Thank you for your interest in contributing to Orchestra! This guide covers
the development setup, testing commands, coding standards, and pull request
process.

---

## Development setup

### Prerequisites

- **Rust** 1.76+ (stable) — [rustup.rs](https://rustup.rs)
- **C compiler** — `gcc`/`clang` (Linux/macOS), Visual Studio Build Tools (Windows)
- **OpenSSL** development headers
- **pkg-config**
- **Git**

### Clone and build

```sh
git clone https://github.com/t-h-i-n-k-er/orchestra.git
cd orchestra
cargo build --workspace
```

### Verify your setup

```sh
./scripts/verify-setup.sh
```

This checks all required and optional dependencies and prints a pass/fail report.

### Development workflow

For rapid iteration during development:

```sh
# Start the Control Center with test credentials:
cargo run -p orchestra-server -- \
    --admin-token devtoken --agent-secret devsecret

# In another terminal, build and run a debug agent:
ORCHESTRA_C=127.0.0.1:8444 ORCHESTRA_SECRET=devsecret \
    cargo run -p agent --bin agent-standalone --features outbound-c

# Or use the dev helper:
./scripts/dev-start.sh
```

---

## Testing

### Run all tests

```sh
cargo test --workspace
```

### Run tests for a specific crate

```sh
cargo test -p common
cargo test -p agent
cargo test -p orchestra-server
```

### Run specific test

```sh
cargo test -p agent -- test_name
```

### Run end-to-end tests

```sh
# Agent ↔ server round-trip
cargo test -p orchestra-server --test e2e

# Outbound agent connection
cargo test -p orchestra-server --test outbound_e2e

# WebSocket authentication
cargo test -p orchestra-server --test ws_auth

# Identity binding
cargo test -p orchestra-server --test identity

# Skip the cargo build step in outbound tests (faster CI):
SKIP_BUILD_TEST=1 cargo test -p orchestra-server --test outbound_e2e
```

### Run benchmarks

```sh
cargo bench -p agent --bench agent_benchmark
```

### Long-running soak test

```sh
ORCHESTRA_SOAK_HOURS=1 cargo test --release --test soak_test
```

---

## Linting and formatting

### Clippy

```sh
cargo clippy --workspace -- -D warnings
```

All code must pass clippy with no warnings. The only allowed exception is
the plugin loader's `#[allow(improper_ctypes_definitions)]` which is required
by the FFI calling convention.

### Formatting

```sh
cargo fmt --all -- --check
```

All code must be formatted with `cargo fmt`. Unformatted code will fail CI.

### Audit

```sh
cargo audit
```

CI runs this on every push. Fix any reported vulnerabilities before submitting
a PR.

---

## Coding standards

### Rust conventions

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).
- Use `#[cfg(target_os = "...")]` for platform-specific code so the workspace
  compiles on all platforms without warnings.
- Add `// SAFETY:` comments on every `unsafe` block explaining why invariants
  are met.
- Use `Result<T>` with descriptive error types — avoid `unwrap()` in library code.
- Prefer `anyhow::Result` for application code, `thiserror` for library error types.

### Security considerations

- **Path validation**: All filesystem I/O must go through `fsops::validate_path`.
- **No hard-coded secrets**: Credentials must be supplied at runtime.
- **Audit logging**: All command handlers must produce audit events.
- **Sensitive data**: File contents and shell I/O must be redacted in audit logs
  via `sanitize_result()`.

### Testing requirements

- Every new feature must include unit tests.
- Bug fixes must include regression tests.
- Platform-specific code must compile (but not necessarily pass tests) on all
  platforms — gate with `#[cfg]` and `#[ignore]` where needed.

### Commit messages

- Use present tense, imperative mood: "Add feature" not "Added feature".
- Reference issue numbers when applicable: "Fix path traversal in module deploy (#42)".
- Keep the first line under 72 characters.

---

## Pull request process

1. **Fork** the repository and create a feature branch.
2. **Write** your changes with appropriate tests.
3. **Run** the full test suite: `cargo test --workspace`.
4. **Run** clippy: `cargo clippy --workspace -- -D warnings`.
5. **Run** formatter: `cargo fmt --all -- --check`.
6. **Commit** with a clear message describing the change.
7. **Push** to your fork and open a pull request against `main`.

### CI checks

All PRs must pass:

- `cargo test --workspace` on Linux
- `cargo clippy --workspace -- -D warnings`
- `cargo fmt --all -- --check`
- `cargo audit`

### Review criteria

- Tests cover the new functionality or fix.
- No clippy warnings.
- `unsafe` blocks have `// SAFETY:` comments.
- Path validation is used for any filesystem operations.
- Audit events are generated for command handlers.
- Sensitive data is redacted in audit logs.

---

## Reporting security issues

Please report security vulnerabilities privately via GitHub Security Advisories
rather than opening a public issue. See the repository's Security tab for
details.

---

## Sign-off

By contributing to Orchestra, you agree that your contributions will be
licensed under the same license as the project.

---

## See also

- [QUICKSTART.md](QUICKSTART.md) — Getting started guide
- [ARCHITECTURE.md](ARCHITECTURE.md) — Internal design reference
- [SECURITY.md](SECURITY.md) — Security audit and hardening guide
- [FEATURES.md](FEATURES.md) — Feature flag reference
