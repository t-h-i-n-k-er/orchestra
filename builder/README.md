# Orchestra Builder

`orchestra-builder` is the unified CLI for producing deployable Orchestra
agent payloads. It wraps dependency setup, profile management, cross-compilation,
binary stripping, and AES-256-GCM encryption into a single tool that an
enterprise IT administrator can run end-to-end without learning the rest of the
workspace layout.

```text
orchestra-builder <COMMAND>

Commands:
  setup           Verify host has all required toolchains/packages
  configure       Interactively create a new profile and save it under profiles/
  list-profiles   List all profiles/*.toml entries
  show-profile    Print a single profile's contents
  build           Build the agent for a profile and emit dist/<name>.enc
  build-launcher  Build the launcher binary that pairs with a profile
```

## Install

The builder is a regular workspace crate; build it once with cargo:

```sh
cargo build --release -p builder
# binary lands at target/release/orchestra-builder
```

## 1. Set up your build host

```sh
orchestra-builder setup
# Optionally let it run `rustup target add ...` for missing rust targets:
orchestra-builder setup --auto-install
```

`setup` verifies that the following are present and prints actionable
install hints when anything is missing:

- `cargo` and `rustup`
- A working C toolchain (`cc` / `cl.exe`) and `pkg-config`
- `mingw-w64` (on Linux hosts) for cross-compiling Windows binaries
- The Rust targets `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-gnu`,
  and `x86_64-apple-darwin`

The builder *never* runs `sudo` automatically. System-package commands are
printed for you to copy-paste; only `rustup target add` is run automatically
(and only with `--auto-install`, after a `y/N` confirmation prompt).

## 2. Create a profile

```sh
orchestra-builder configure --name windows_stealth
```

This launches an interactive wizard that asks for:

- Target OS (`linux` / `windows` / `macos`) and architecture (`x86_64` /
  `aarch64`) — converted internally to a Rust target triple
- C2 address (`host:port`)
- Encryption key — generate a fresh 32-byte AES key, paste a base64 key, or
  reference a key file via `file:/path/to/key.bin`
- Cargo features to enable on the agent crate (multi-select). Recognised
  flags include `persistence`, `network-discovery`, `hci-research`,
  `perf-optimize`, `direct-syscalls`, `manual-map`,
  `traffic-normalization`, and `env-validation`. Unknown flags are passed
  straight to cargo and rejected if not declared.
- Optional output filename override

The result is written to `profiles/<name>.toml`, for example:

```toml
target_os = "windows"
target_arch = "x86_64"
c2_address = "10.0.0.5:7890"
encryption_key = "aGVsbG8tdGVzdC1rZXktMzItYnl0ZXMtZXhhY3RseSE="
features = ["persistence", "traffic-normalization"]
package = "launcher"
```

The `package` field controls which Cargo crate is built as the deployable
binary. It defaults to `launcher` (in-memory payload delivery); set
`package = "agent"` and `bin_name = "agent-standalone"` together with the
`outbound-c` feature to produce a self-contained agent binary instead.

### Outbound-mode (agent dials the Control Center)

The `outbound-c` feature turns the agent into a binary that automatically
connects to the Orchestra Control Center and reconnects on disconnection.
The Builder bakes the server address and PSK directly into the binary at
compile time so no separate configuration file is required on the endpoint.

When the `configure` wizard detects that you have selected `outbound-c`:

* It prompts for the Control Center pre-shared secret.
* It automatically switches `package` to `"agent"` and `bin_name` to
  `"agent-standalone"`.
* It passes `ORCHESTRA_C_ADDR` and `ORCHESTRA_C_SECRET` as environment
  variables to `cargo build`, where `option_env!()` in the agent source
  captures them at compile time.

Example profile (can be created by the wizard or written by hand):

```toml
target_os         = "linux"
target_arch       = "x86_64"
c2_address        = "10.0.0.5:8444"
encryption_key    = "<base64-32-bytes>"
c_server_secret   = "REPLACE-ME-same-as-agent_shared_secret-in-server-toml"
features          = ["outbound-c"]
package           = "agent"
bin_name          = "agent-standalone"
```

Build:

```sh
orchestra-builder build prod-outbound
# -> dist/prod-outbound.enc (AES-encrypted agent-standalone binary)
```

The runtime override env vars (`ORCHESTRA_C` and `ORCHESTRA_SECRET`) take
precedence over the baked-in values, so you can repurpose a binary without
rebuilding it.

See [`docs/C_SERVER.md`](../docs/C_SERVER.md) for the full orchestration
picture and the outbound-agent self-verification test.

### Inspect & list profiles

```sh
orchestra-builder list-profiles
orchestra-builder show-profile windows_stealth
```

## 3. Build a payload

```sh
orchestra-builder build windows_stealth
```

The build pipeline:

1. Loads `profiles/windows_stealth.toml` and validates the encryption key.
2. Resolves the Rust target triple from `target_os` / `target_arch`.
3. Runs `cargo build --release --target <triple> -p <package> --features <flags>`,
   forwarding stdout/stderr so you see compiler progress.
4. Locates the resulting binary at
   `target/<triple>/release/<package>[.exe]`.
5. Best-effort strip via `strip` (skipped silently if not on `PATH`).
6. Encrypts the binary with AES-256-GCM via `common::CryptoSession`
   (12-byte nonce ‖ ciphertext+tag — the exact format the launcher expects).
7. Writes `dist/<output_name>.enc` (defaults to `dist/<profile_name>.enc`).

If the profile enables `traffic-normalization`, also build the matching
launcher (this forwards just the launcher-relevant features):

```sh
orchestra-builder build-launcher windows_stealth
# -> dist/windows_stealth-launcher[.exe]
```

## End-to-end verification

```sh
cargo clean
orchestra-builder setup
orchestra-builder configure --name linux_demo   # accept defaults
orchestra-builder build linux_demo
ls -lh dist/                                    # see the .enc
```

The encrypted payload can then be served by `cargo run -p dev-server -- --port 8000`
and consumed by `cargo run -p launcher -- --url http://127.0.0.1:8000/linux_demo.enc --key <base64-key>`.
