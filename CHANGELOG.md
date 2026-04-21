# Changelog

All notable changes to Orchestra are documented here.

---

## [Unreleased]

### Added

#### `agent` crate
- **`env_check` module** — Trusted Execution Environment (TEE) enforcement:
  `is_debugger_present()`, `detect_vm()`, `validate_domain(required)`, and
  `enforce()`. Agents can be configured to terminate or degrade gracefully when
  running outside an approved execution context (no debugger, no hypervisor,
  correct Active Directory domain).
- **`remote_assist` updated for enigo 0.2 API** — Constructor changed to
  `Enigo::new(&Settings::default())?`, `key_sequence` replaced by `.text()`,
  `mouse_move_to` replaced by `.move_mouse(x, y, Coordinate::Abs)`.
- **enigo `x11rb` backend** — Linux build now uses `default-features = false,
  features = ["x11rb"]` for `enigo`, eliminating the `libxdo-dev` system
  dependency while retaining full X11 keyboard/mouse simulation.
- **`x11cap` vendor patch** — Local fork of `x11cap 0.1.0` at `vendor/x11cap/`
  replaces the removed `Unique<T>` nightly feature with `NonNull<T>`, allowing
  compilation on stable Rust 1.95+. RGB8 fields are now `pub`.

#### `builder` crate
- **Runtime feature discovery** — `config::read_agent_features()` parses
  `agent/Cargo.toml` at runtime so the interactive configure menu always
  reflects the current feature set without manual maintenance.
- **Unknown-feature guard** — `partition_features()` splits user-requested
  features into known and unknown sets; unknown features emit a warning and are
  excluded from the build invocation.

#### `console` crate
- **11 new subcommands**: `discover`, `screenshot`, `key`, `mouse`,
  `hci-start`, `hci-stop`, `hci-log`, `persist-enable`, `persist-disable`,
  `list-procs`, `migrate` — covering network discovery, remote assistance,
  HCI research logging, persistence control, process enumeration, and
  cross-process task migration.
- **Interactive REPL modes** for `key` (`--repl`) and `mouse` (`--repl`)
  subcommands: read-eval-print loops that dispatch each line without
  round-tripping the TLS handshake.

#### `hollowing` crate (new)
- Shared crate implementing Windows process hollowing (`hollow_and_execute`).
  Returns `Err("only available on Windows")` on non-Windows targets, enabling
  cross-platform compilation.
- `launcher` now calls `hollowing::hollow_and_execute` for in-memory payload
  execution on Windows.

#### Documentation
- `docs/USER_GUIDE.md` §10: Trusted Execution Environment Enforcement.
- `docs/LAUNCHER.md` (new): Windows hollowing, per-platform execution table,
  RunPE sequence diagram.
- `console/README.md` (new): Full subcommand reference with flags and examples.
- `builder/README.md`: Feature flags are discovered at runtime from
  `agent/Cargo.toml`.
- `README.md`: Expanded console subcommand table (17 commands), docs links,
  env-validation description.

### Fixed

- `module_loader` — `MODULE_SIGNING_PUBKEY` was incorrectly reused as both a
  signing seed and a verifying key. Replaced with the actual 32-byte compressed
  point (verifying key) derived from the test seed, stored in a separate
  `MODULE_TEST_SIGNING_SEED` constant. Both tests (`test_load_and_execute_plugin`
  and `test_tampered_module_fails_verification`) now use consistent keys and pass
  with `--features module-signatures`.
- `common` — Removed manual `impl Default for TrafficProfile` and replaced with
  `#[derive(Default)]` + `#[default]` on the `Raw` variant (clippy
  `derivable_impls`).
- `agent/env_check` — Replaced `.iter().any(|p| *p == prefix)` with
  `.contains(&prefix)` (clippy `manual_contains`).
- `image 0.25` — Replaced removed `ImageOutputFormat::Png` with
  `image::ImageFormat::Png`.
- `ed25519-dalek 2.1` — Added `use ed25519_dalek::Signer;` where `.sign()` is
  called.

### Build

- `cargo test --workspace --all-features` — **all tests pass** on Linux.
- `cargo clippy --workspace --all-features -- -D warnings` — **zero warnings**.
- `cargo fmt --all` — workspace fully formatted.
