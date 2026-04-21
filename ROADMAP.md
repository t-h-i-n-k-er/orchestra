# Orchestra Roadmap

The Orchestra framework is feature-complete for its initial milestone:
encrypted console-to-agent control, file and shell operations under a
strict allow-list, dynamic capability plugins, opt-in persistence and
remote-assistance modules, structured audit logging, and mutually-
authenticated TLS transport.

This document describes where the project is going next.

---

## Short term (next 0–3 months)

- **Web GUI console.** A small Axum + React front-end that talks to the
  same `Transport` as the CLI. Shipped as a single static binary.
- **SSH transport.** An additional `Transport` implementation that
  tunnels protocol frames inside an SSH channel, useful for sites where
  exposing a dedicated TLS port is inconvenient.
- **HMAC-signed audit events** for tamper-evident compliance logs.
- **`orchestra-agentd` reference daemon** so administrators don't have
  to write their own wrapper to embed the agent library.
- **Windows MSI installer** built in CI from the release artifacts.

## Medium term (3–9 months)

- **Plugin marketplace.** A signed, public registry from which
  administrators can pull pre-vetted capability modules. Includes a
  reference indexer + signature-verification CLI.
- **Kubernetes node support.** A DaemonSet that runs the agent inside
  every node, exposing pod-level diagnostics through dedicated commands.
- **Sandboxed plugin execution.** seccomp-bpf on Linux and Job Objects on
  Windows to constrain what a loaded plugin can syscall.
- **Authenticated key exchange.** Replace the development pre-shared-key
  path with X25519 + HKDF, so even non-TLS deployments get forward
  secrecy.
- **Per-operator RBAC.** Bind the operator certificate's CN to a role
  and restrict commands accordingly (e.g., `read-only`, `operator`,
  `administrator`).

## Long term (9+ months)

- **Enterprise identity-provider integration.** LDAP/Active Directory
  and OAuth/OIDC for issuing operator client certificates from existing
  identity sources.
- **Streaming telemetry.** Optional, opt-in metrics export (OpenTelemetry)
  for centralized observability of large fleets.
- **Hot-reloadable agent core.** Use the in-memory module loader to swap
  the agent binary itself without restarting, keeping shell sessions
  alive across upgrades.
- **Formal verification of `validate_path`.** Prove the path-traversal
  guard correct using `prusti` or `kani`.

---

## How to contribute

1. **Find an item** above (or open an issue describing your idea).
2. Open a draft PR early; we discuss design before merging code.
3. Run `cargo fmt --all`, `cargo clippy --workspace -- -D warnings`,
   `cargo test --workspace`, and `cargo audit` locally before pushing.
4. Add or update entries in `docs/DESIGN.md` for any user-visible
   behaviour change.
5. Sign your commits (`git commit -s`) under the
   [Developer Certificate of Origin](https://developercertificate.org/).

Security-sensitive contributions (new transports, anything inside
`module_loader`, anything that takes user-supplied paths) get an
additional reviewer from the security team. Please be patient with the
extra round-trip — it exists so we can keep the project trustworthy.

---

## Project capabilities, in neutral language

Orchestra today provides:

- A console CLI and a reusable agent library implemented in safe Rust.
- Mutually-authenticated TLS transport (rustls 0.23) plus a
  pre-shared-key TCP transport for development.
- An allow-listed file API, an interactive PTY shell, system-info
  collection, opt-in network discovery, opt-in remote-assistance, and
  opt-in HCI usage logging — each guarded by an explicit feature flag
  and, where applicable, a consent file.
- A signed-and-encrypted plugin loader that executes capability modules
  in process memory.
- Structured per-command audit logging written as JSON-lines.
- Configurable policy enforcement via TOML, hot-reloadable at runtime.
- Cross-platform CI for Linux, macOS, and Windows, plus a `cargo audit`
  job and a tag-driven release workflow that produces signed archives.

Orchestra is intended for use by authorized administrators on systems
they own or are explicitly authorized to manage.
