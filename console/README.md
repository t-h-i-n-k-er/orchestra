# Orchestra Console

Direct command-line client for the Orchestra agent.

> **Deployment model note:** This tool implements **direct connection** (Model A)
> — it connects straight to an agent's TCP/TLS listener.  For production
> multi-agent deployments where agents are registered with `orchestra-server`,
> use the server's HTTPS API (`POST /agents/<id>/command`) or the web UI
> at `https://<server>:8443` instead.  See `docs/USER_GUIDE.md` for details.

```text
orchestra-console --target HOST:PORT --key BASE64 <SUBCOMMAND>
orchestra-console --target HOST:PORT --tls --ca-cert CA.pem \
                  --client-cert CLIENT.pem --client-key CLIENT.key <SUBCOMMAND>
```

## Subcommands

| Subcommand          | Sends `Command::…`        | Notes                                        |
| ------------------- | ------------------------- | -------------------------------------------- |
| `ping`              | `Ping`                    | Simple liveness check.                       |
| `info`              | `GetSystemInfo`           | Host inventory.                              |
| `shell`             | `StartShell` + I/O loop   | Interactive PTY session.                     |
| `upload L R`        | `WriteFile{R, …}`         | Upload local file `L` to remote path `R`.    |
| `download R L`      | `ReadFile{R}`             | Save remote file `R` to local path `L`.      |
| `deploy <module>`   | `DeployModule`            | Stage a capability module by id.             |
| `reload-config`     | `ReloadConfig`            | Re-read `agent.toml` on the endpoint.        |
| `discover`          | `DiscoverNetwork`         | LAN/host enumeration.                        |
| `screenshot`        | `CaptureScreen`           | Save returned image (`--out screenshot.png`).|
| `key <K> [--repl]`  | `SimulateKey{K}`          | Single key, or REPL fed from stdin.          |
| `mouse X Y [--repl]`| `SimulateMouse{X,Y}`      | Single move, or REPL with `x y` per line.    |
| `hci-start`         | `StartHciLogging`         | Begin Bluetooth HCI capture.                 |
| `hci-stop`          | `StopHciLogging`          | Stop capture.                                |
| `hci-log`           | `GetHciLogBuffer`         | Drain buffered HCI events.                   |
| `persist-enable`    | `EnablePersistence`       | Install systemd unit / scheduled task.       |
| `persist-disable`   | `DisablePersistence`      | Remove persistence.                          |
| `list-procs`        | `ListProcesses`           | JSON snapshot of the process table.          |
| `migrate <pid>`     | `MigrateAgent{target_pid}`| Windows: process hollowing into target PID.  |

## Self-verification

Use `cargo test -p orchestra-server --test outbound_e2e` for the supported
agent/server happy path. Console subcommands require a custom test listener
that speaks the shared `Message` protocol.

## REPL mode

`key --repl` reads one key per line from stdin and dispatches a separate
`SimulateKey` per line; `mouse --repl` reads `x y` pairs. Both terminate
on EOF or on the literal line `quit`.
