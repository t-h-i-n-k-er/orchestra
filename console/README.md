# Orchestra Console

Command-line client for an Orchestra agent. Connects either with the
pre-shared-key TCP transport (development / lab) or with a fully
mutual-TLS transport (production).

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

Spin up a local agent and exercise every subcommand:

```sh
# Terminal 1: agent
cargo run -p agent --bin agent-standalone --features outbound-c

# Terminal 2: console (PSK mode for local development)
KEY=$(head -c32 /dev/urandom | base64)
orchestra-console --target 127.0.0.1:7890 --key "$KEY" ping
orchestra-console --target 127.0.0.1:7890 --key "$KEY" info
orchestra-console --target 127.0.0.1:7890 --key "$KEY" list-procs
orchestra-console --target 127.0.0.1:7890 --key "$KEY" discover
echo Hello | orchestra-console --target 127.0.0.1:7890 --key "$KEY" key --repl
echo "100 200" | orchestra-console --target 127.0.0.1:7890 --key "$KEY" mouse --repl
```

Each subcommand prints the agent's `TaskResponse.result` to stdout (or the
error from a refused command) and persists `AuditLog` events to
`audit.log` in the working directory.

## REPL mode

`key --repl` reads one key per line from stdin and dispatches a separate
`SimulateKey` per line; `mouse --repl` reads `x y` pairs. Both terminate
on EOF or on the literal line `quit`.
