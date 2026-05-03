# P2P Mesh Networking — Full Reference

> **Status**: Production-ready.  All mesh features require the `p2p-tcp` (or
> `smb-pipe-transport` on Windows) feature flag at build time.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Wire Protocol Reference](#wire-protocol-reference)
3. [Routing Protocol](#routing-protocol)
4. [Link Quality Monitoring](#link-quality-monitoring)
5. [Link Healing & Reconnection](#link-healing--reconnection)
6. [Security Model](#security-model)
7. [Server Commands Reference](#server-commands-reference)
8. [Compartment Configuration](#compartment-configuration)
9. [Troubleshooting](#troubleshooting)
10. [Performance Characteristics](#performance-characteristics)

---

## Architecture Overview

### Topology Modes

The Orchestra mesh supports three topology modes, selectable per-agent at
configuration time via the `mesh_mode` field:

| Mode | Description | Peer Links | Route Discovery | Best For |
|------|-------------|:----------:|:---------------:|----------|
| **Tree** | Strict parent–child hierarchy | ✗ | ✗ | Maximum OPSEC; all traffic funneled through parents to server |
| **Mesh** | Full peer-to-peer with route discovery | ✓ | ✓ | Maximum resilience; lateral communication between any agents |
| **Hybrid** | Tree backbone with optional peer links | ✓ | ✓ | Balanced — tree for C2 relay, peers for low-latency lateral |

**Default**: `Hybrid`

### Topology Diagram

```
                         ┌──────────┐
                         │  Server  │
                         │ (C2)     │
                         └────┬─────┘
                              │ TCP/TLS
                         ┌────▼─────┐
                         │ Agent A  │ (parent, internet-facing)
                         │ MeshMode │
                         └─┬──┬──┬─┘
             C2 relay      │  │  │     C2 relay
              (up)    ┌────┘  │  └────┐
                      │       │       │
                 ┌────▼──┐ ┌──▼───┐ ┌─▼─────┐
                 │Agent B│ │Agent │ │Agent E│
                 │       │ │  D   │ │       │
                 └─┬──┬──┘ └──────┘ └───────┘
            peer  │  │ child
           link   │  │
          ┌───────┘  └─────┐
          │                │
     ┌────▼──┐        ┌───▼────┐
     │Agent C│        │Agent F │
     │(child │        │(child  │
     │ of B) │        │ of B)  │
     └───────┘        └────────┘
```

- **Agent A** is directly connected to the server (first-hop parent).
- **Agent B** and **Agent D** are children of Agent A.
- **Agent C** and **Agent F** are children of Agent B (nested).
- **Peer link** between Agent B and a neighbor at the same level enables
  lateral communication without traversing the server.

### Link Types

| Link Type | Direction | Purpose |
|-----------|-----------|---------|
| `Parent` | Agent → Server (upstream) | C2 relay; carries commands and results |
| `Child` | Server → Agent (downstream) | C2 relay to nested agents |
| `Peer` | Agent ↔ Agent (lateral) | Mesh/Hybrid only; direct lateral communication |

### Message Routing

| Direction | Frame Type | Path |
|-----------|-----------|------|
| Agent → Server | `DataForward` | Up through parent chain |
| Server → Agent | `DataToChild` | Down through parent chain via `link_id` |
| Agent ↔ Agent | `DataForward` / `DataToChild` | Through routing table next-hops |

---

## Wire Protocol Reference

### Frame Header

All P2P frames share a common 10-byte header:

```
┌──────────────┬─────────────┬───────────────┬─────────────────┐
│ type (1B)    │ link_id (4B)│ payload_len   │ payload         │
│ P2pFrameType │   LE        │ (4B) LE       │ (payload_len B) │
└──────────────┴─────────────┴───────────────┴─────────────────┘
```

- `type` and `link_id` are **not encrypted** (routing header).
- `payload` is encrypted with the per-link ChaCha20-Poly1305 key
  (nonce ‖ ciphertext ‖ tag).

### Frame Types

| Value | Name | Direction | Purpose |
|-------|------|-----------|---------|
| `0x30` | `LinkRequest` | Child → Parent | Initiate a new P2P link |
| `0x31` | `LinkAccept` | Parent → Child | Accept link request (includes parent's X25519 pubkey) |
| `0x32` | `LinkReject` | Parent → Child | Reject link request (includes reason code) |
| `0x33` | `Heartbeat` | Bidirectional | Keep-alive + latency probe |
| `0x34` | `Disconnect` | Bidirectional | Graceful link teardown |
| `0x35` | `DataForward` | Child → Parent | Relay data toward C2 server |
| `0x36` | `CertificateRevocation` | Server → Agents | Revoke a mesh certificate |
| `0x37` | `QuarantineReport` | Agent → Server | Report a quarantined agent |
| `0x38` | `KeyRotation` | Initiator → Responder | Start per-link key rotation |
| `0x39` | `KeyRotationAck` | Responder → Initiator | Acknowledge key rotation |
| `0x3A` | `RouteUpdate` | Bidirectional | Distance-vector route advertisement |
| `0x3B` | `RouteProbe` | Bidirectional | Measure link latency/hops |
| `0x3C` | `RouteProbeReply` | Bidirectional | Reply to route probe |
| `0x3D` | `DataAck` | Bidirectional | Acknowledge data delivery |
| `0x3E` | `TopologyReport` | Agent → Server | Report mesh topology |
| `0x3F` | `BandwidthProbe` | Bidirectional | Measure available bandwidth |

### Frame Payload Formats

#### LinkRequest (`0x30`)

```
┌──────────────────┬────────────────────┬──────────────────────┐
│ agent_id_len(2B) │ agent_id(var)      │ x25519_pubkey(32B)   │
 │     LE           │                    │                      │
└──────────────────┴────────────────────┴──────────────────────┘
```

#### LinkAccept (`0x31`)

```
┌──────────────────────────┐
│ parent_x25519_pubkey(32B)│
└──────────────────────────┘
```

After reception, both sides compute:
```
shared_secret = X25519(our_secret, their_public)
link_key = HKDF-SHA256(salt=None, ikm=shared_secret, info="orchestra-p2p-link-key")
```

#### LinkReject (`0x32`)

```
┌──────────────┐
│ reason (1B)  │
└──────────────┘
```

| Reason | Meaning |
|--------|---------|
| `0x01` | Capacity full (max children reached) |
| `0x02` | Authentication failure |
| `0x03` | Agent revoked |
| `0x04` | Compartment mismatch |

#### KeyRotation (`0x38`)

```
┌──────────────────────────────────┐
│ new_ephemeral_public_key (32B)   │
└──────────────────────────────────┘
```

#### KeyRotationAck (`0x39`)

```
┌──────────────────────────────────┐
│ responder_new_public_key (32B)   │
└──────────────────────────────────┘
```

#### CertificateRevocation (`0x36`)

```
┌──────────────────────────────────┐
│ revoked_agent_id_hash (32B)      │
└──────────────────────────────────┘
```

#### QuarantineReport (`0x37`)

```
┌──────────────────────────────────┬──────────────┬──────────────────┐
│ quarantined_agent_id_hash (32B)  │ reason (1B)  │ evidence_hash(32)│
└──────────────────────────────────┴──────────────┴──────────────────┘
```

#### RouteUpdate (`0x3A`)

```
┌─────────────────┬──────────────────────────────────────────┐
│ entry_count (1B)│ RouteEntry × entry_count                 │
│                 │ [dest(4B) | next_hop(4B) | hops(1B) |    │
│                 │  quality(4B f32)]                        │
└─────────────────┴──────────────────────────────────────────┘
```

#### RouteProbe / RouteProbeReply (`0x3B` / `0x3C`)

```
┌──────────────┬──────────────┬───────────────────┐
│ probe_id(4B) │ sender(4B)   │ hop_count(1B)     │
│     LE       │    LE        │                   │
└──────────────┴──────────────┴───────────────────┘
```

#### BandwidthProbe (`0x3F`)

```
┌──────────────┬─────────────────────────────────┐
│ probe_id(4B) │ payload (variable, 1–16 KiB)    │
│     LE       │                                 │
└──────────────┴─────────────────────────────────┘
```

---

## Routing Protocol

### Distance-Vector Algorithm

The Orchestra mesh uses a distributed distance-vector routing protocol:

1. Each agent maintains a **routing table** mapping `destination → RouteEntry`.
2. Every **60 seconds** (`ROUTE_UPDATE_INTERVAL_SECS`), each agent advertises
   its routing table to all connected peers via `RouteUpdate` frames.
3. When an agent receives a `RouteUpdate`, it applies the Bellman-Ford update
   rule:
   - For each advertised route, compute: `new_cost = advertised_cost + link_cost`
   - If `new_cost < existing_cost`, update the route entry.
4. Routes with quality below `ROUTE_MIN_QUALITY` (0.1) are discarded.

### Route Quality Scoring

Quality is a composite metric (0.0–1.0, higher is better):

$$Q = 0.4 \cdot Q_{lat} + 0.4 \cdot Q_{loss} + 0.2 \cdot Q_{jitter}$$

Where:
- $Q_{lat} = \min(1.0,\ 100 / \text{latency\_ms})$ — latency score
- $Q_{loss} = 1.0 - \text{packet\_loss}$ — loss score
- $Q_{jitter} = \min(1.0,\ 50 / (\text{jitter\_ms} + 1))$ — jitter score

### Relay Selection

When forwarding data, the agent selects the best next-hop relay using:

$$\text{score} = 0.7 \cdot Q_{route} + 0.3 \cdot \frac{1}{\text{hop\_count}}$$

If multiple routes score within 10% of each other, a weighted round-robin
distributes traffic across them for load balancing.

### Route Lifecycle

| State | Condition |
|-------|-----------|
| **Active** | Updated within `ROUTE_STALE_SECS` (300s) and quality ≥ 0.1 |
| **Stale** | Not updated for 300s — still usable but penalized |
| **Expired** | Not updated for 600s — removed from table |
| **Dead** | Link carrying the route died — immediately removed |

---

## Link Quality Monitoring

### Metrics Per Link

| Metric | Unit | Source |
|--------|------|--------|
| Latency | ms (smoothed avg) | Heartbeat RTT / 2 |
| Jitter | ms (stddev) | Variance of recent samples |
| Packet Loss | 0.0–1.0 | Missed heartbeat ratio |
| Bandwidth | bps (EMA α=0.3) | Bandwidth probe results |
| Uptime | seconds | Time since link established |

### Heartbeat Protocol

- **Interval**: Configurable per-link (default 30s).
- **Timeout**: `DEAD_THRESHOLD` (8) consecutive misses → link declared dead.
- **Loss tracking**: Every `LOSS_THRESHOLD` (4) misses → packet_loss += 0.05.

### Bandwidth Probes

- Periodic `BandwidthProbe` frames (1–16 KiB payload) measure throughput.
- Results smoothed with exponential moving average (α = 0.3).
- Used for relay selection and congestion detection.

### Congestion Detection

| Threshold | Condition | Action |
|-----------|-----------|--------|
| **High** | Pending data > 64 KiB | Route quality penalized by 50% |
| **Low** | Pending data < 16 KiB | Route quality restored to base |

Congestion state is tracked per-link and triggers automatic route quality
adjustment.

---

## Link Healing & Reconnection

### Dead Link Detection

A link is declared dead when any of these occur:

1. **Heartbeat timeout**: `DEAD_THRESHOLD` (8) consecutive missed heartbeats.
2. **Read error**: TCP connection reset or pipe closed.
3. **Kill switch**: Operator-initiated mesh-wide termination.
4. **Certificate revocation**: Peer's certificate was revoked by the server.

### Automatic Recovery

When a link dies:

1. **Route cleanup**: All routes using the dead link are immediately removed
   from the routing table.
2. **Reconnection**: If the link was to a parent (upstream), the agent enters
   an exponential backoff reconnection loop (`ReconnectBackoff`).
3. **Route rediscovery**: After reconnecting, the agent floods `RouteProbe`
   frames to rebuild its routing table.
4. **Fallback relay**: If no direct route exists, data is relayed through
   the server (tree fallback).

### Reconnection Backoff

```
attempt 1: wait 5s
attempt 2: wait 10s
attempt 3: wait 20s
attempt 4: wait 40s
...
max wait: 300s (5 minutes)
```

Backoff is reset to 5s on successful reconnection.

---

## Security Model

### Trust Hierarchy

```
         ┌──────────────┐
         │   Server     │  Holds Ed25519 signing key
         │  (Root CA)   │  (module_signing_key)
         └──────┬───────┘
                │ signs
         ┌──────▼───────┐
         │ MeshCert     │  Server-signed certificate
         │ (per-agent)  │  Binds agent_id_hash → public_key
         └──────┬───────┘
                │ presented during handshake
         ┌──────▼───────┐
         │ P2P Link     │  Per-link ChaCha20-Poly1305
         │ (encrypted)  │  X25519 ECDH → HKDF-derived key
         └──────────────┘
```

### Mesh Certificates

Each agent receives a `MeshCertificate` from the server upon checkin:

| Field | Size | Purpose |
|-------|------|---------|
| `agent_id_hash` | 32B | SHA-256 of agent_id (privacy-preserving identity) |
| `public_key` | 32B | Agent's Ed25519 public key |
| `issued_at` | 8B | Unix timestamp of issuance |
| `expires_at` | 8B | Unix timestamp of expiry (24h lifetime) |
| `server_signature` | 64B | Ed25519 signature over canonical body |
| `compartment` | variable | Optional compartment tag |

**Lifecycle**:
1. **Issuance**: Server issues cert on first heartbeat when `module_signing_key`
   is configured.
2. **Verification**: During P2P handshake, each agent verifies the peer's cert
   against the server's Ed25519 public key.
3. **Renewal**: Agent requests renewal when cert enters 2-hour renewal window
   (2h before expiry).
4. **Revocation**: Server can revoke certs by agent_id_hash; revocation
   propagates through the mesh via `CertificateRevocation` frames.

### Per-Link Encryption

```
Agent A                          Agent B
  │                                │
  │  X25519 ECDH key exchange      │
  │  (during LinkRequest/Accept)   │
  │                                │
  │  shared = DH(A_priv, B_pub)    │
  │  key = HKDF-SHA256(            │
  │    salt=None,                  │
  │    ikm=shared,                 │
  │    info="orchestra-p2p-link-key"│
  │  )                             │
  │                                │
  │  ◄── ChaCha20-Poly1305 ──►    │
  │  nonce(12) ‖ ct ‖ tag(16)     │
```

### Key Rotation

Every **4 hours** (`KEY_ROTATION_INTERVAL_SECS`), links undergo key rotation:

```
Initiator                          Responder
   │                                  │
   │  generate new X25519 ephemeral   │
   │  ──── KeyRotation ────────────►  │
   │  {new_ephemeral_pubkey}          │  generate own X25519 ephemeral
   │                                  │  derive new shared secret
   │                                  │  apply new key
   │  ◄── KeyRotationAck ──────────  │
   │  {responder_new_pubkey}          │  (encrypted with OLD key)
   │                                  │
   │  derive new shared secret        │
   │  apply new key                   │
   │                                  │
   │  ◄── ChaCha20-Poly1305 ──►      │
   │  (encrypted with NEW key)        │
```

**Key rotation properties**:
- **Overlap period**: 30 seconds where both old and new keys are accepted.
- **Timeout**: 60 seconds — if no `KeyRotationAck`, rotation is retried.
- **Retry limit**: 3 retries before marking rotation as failed.
- **Backward secrecy**: Old key is retained only for overlap, then zeroized.

### Compromise Containment

#### Kill Switch

The operator activates a kill switch via `POST /mesh/kill-switch`:

1. Server broadcasts `Command::MeshKillSwitch` to all (or specific) agents.
2. Each agent immediately terminates **all** P2P links.
3. Agent enters isolation mode — only direct server connection remains.

#### Quarantine

The operator quarantines a specific agent via `POST /mesh/quarantine`:

1. Server sends `Command::MeshQuarantine` to the target agent.
2. Target agent marks itself as quarantined and stops relaying data.
3. Neighbors detect quarantine state and route around the agent.
4. Quarantine reports propagate to the server via `QuarantineReport` frames.

#### Compartment Isolation

Agents can be assigned to compartments via `POST /mesh/set-compartment`:

- Agents only form P2P links with agents in the **same compartment**.
- Cross-compartment traffic must traverse the server.
- Compartment is embedded in the mesh certificate.

---

## Server Commands Reference

### Mesh Topology

```
GET /mesh/topology
```

Returns the full mesh topology tree as known to the server.

### Mesh Statistics

```
GET /mesh/stats
```

Returns aggregate mesh statistics (total agents, links, bandwidth).

### Mesh Connect

```
POST /mesh/connect
{
  "parent_agent_id": "DESKTOP-WIN10",
  "child_address": "10.0.0.20:4443"
}
```

Instructs an agent to establish a P2P link to the specified address.

### Mesh Disconnect

```
POST /mesh/disconnect
{
  "agent_id": "DESKTOP-WIN10",
  "link_id": "0x00000001"
}
```

Gracefully terminates a specific P2P link.

### Mesh Kill Switch

```
POST /mesh/kill-switch
{
  "agent_id": "DESKTOP-WIN10"    // optional: omit to broadcast to all
}
```

Immediately terminates all P2P links on the target agent(s).

### Mesh Quarantine

```
POST /mesh/quarantine
{
  "agent_id": "SERVER-COMPROMISED",
  "reason": 2                    // 0=unspecified, 1=invalid_cert, 2=compromise
}
```

Quarantines an agent — stops all relaying but keeps server connection alive.

### Mesh Clear Quarantine

```
POST /mesh/clear-quarantine
{
  "agent_id": "SERVER-RECOVERED"
}
```

Removes quarantine status from an agent.

### Mesh Set Compartment

```
POST /mesh/set-compartment
{
  "agent_id": "DESKTOP-WIN10",
  "compartment": "finance-team"
}
```

Assigns a compartment to an agent. Only agents in the same compartment can
form peer links.

### Mesh Route

```
POST /mesh/route
{
  "from_agent_id": "DESKTOP-WIN10",
  "to_agent_id": "SERVER-DB01"
}
```

Returns the current route between two agents as computed by the server-side
mesh controller.

### Mesh Broadcast

```
POST /mesh/broadcast
{
  "command": "GetSystemInfo",
  "compartment": "finance-team"   // optional
}
```

Broadcasts a command to all agents (optionally filtered by compartment).

---

## Compartment Configuration

### What Are Compartments?

Compartments partition the mesh into isolated groups. Agents in the same
compartment can form peer links and relay data laterally. Cross-compartment
traffic must route through the server.

### Configuration

**Server-side** (via API):

```bash
# Assign agent to compartment
curl -X POST https://c2.example.com/api/mesh/set-compartment \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"agent_id":"DESKTOP-FIN01","compartment":"finance"}'

curl -X POST https://c2.example.com/api/mesh/set-compartment \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"agent_id":"DESKTOP-ENG01","compartment":"engineering"}'
```

**Agent behavior**:
- Agents receive their compartment via `Command::MeshSetCompartment`.
- The compartment is stored in the agent's mesh certificate.
- During handshake, agents compare compartments — mismatched agents reject
  with reason `0x04`.

### Compartment Isolation Diagram

```
┌─── Compartment "finance" ────────────────────┐
│  DESKTOP-FIN01 ←→ DESKTOP-FIN02 ←→ FIN-SRV │
│         (peer links allowed)                 │
└──────────────────────────┬───────────────────┘
                           │ Only via server
┌──────────────────────────▼───────────────────┐
│  DESKTOP-ENG01 ←→ DESKTOP-ENG02             │
│     Compartment "engineering"                │
└──────────────────────────────────────────────┘
```

---

## Troubleshooting

### 1. Agent Can't Join Mesh

**Symptoms**: Agent connects to server but `ListTopology` shows no peers.

**Checks**:
1. Verify agent was built with `p2p-tcp` (or `smb-pipe-transport`) feature:
   ```bash
   orchestra-console send --agent AGENT --command GetSystemInfo
   # Check "features" field includes p2p-tcp
   ```
2. Verify target address is reachable from the agent's network:
   ```bash
   orchestra-console send --agent AGENT-A --command MeshConnect \
     --args "10.0.0.20:4443"
   ```
3. Check if the parent has capacity (max children not exceeded).
4. Check if compartments match — mismatched compartments silently reject.
5. Verify no firewall is blocking the P2P port.

**Resolution**:
- Increase `max_children` on the parent agent's config.
- Assign both agents to the same compartment.
- Check server audit log for `LinkReject` events.

### 2. Link Keeps Dying

**Symptoms**: Links form but repeatedly transition to `Dead` state.

**Checks**:
1. Check heartbeat interval — too aggressive intervals may cause timeouts on
   slow links.
2. Verify network stability between the two agents (ping test).
3. Check if NAT timeout is closing idle connections (set heartbeat < 30s).
4. Review link quality metrics:
   ```bash
   orchestra-console send --agent AGENT --command ListLinks
   ```
5. Check for certificate expiry — certs expire after 24 hours and must be
   renewed.

**Resolution**:
- Reduce heartbeat interval to stay under NAT timeout.
- Increase `DEAD_THRESHOLD` for high-latency environments.
- Verify `module_signing_key` is configured on the server for cert renewal.

### 3. Routes Not Converging

**Symptoms**: `route_to()` returns `None` for known agents; traffic takes
suboptimal paths.

**Checks**:
1. Verify both agents are in Mesh or Hybrid mode (Tree mode has no route
   discovery).
2. Check that `RouteUpdate` frames are being exchanged (increase log level).
3. Verify `ROUTE_UPDATE_INTERVAL_SECS` — default 60s, may need reduction
   for large meshes.
4. Check for asymmetric routes causing routing loops.

**Resolution**:
- Manually trigger a route probe via `RouteProbe`.
- Restart an agent to force full route table rebuild.
- Reduce route update interval for faster convergence.

### 4. Relay Throughput Issues

**Symptoms**: Commands time out when routed through multiple hops; bandwidth
is lower than expected.

**Checks**:
1. Check per-hop latency — each hop adds ~50ms typical overhead.
2. Review bandwidth probe results for bottleneck links.
3. Check congestion detection — links with >64 KiB pending data are penalized.
4. Verify relay throttle settings aren't overly restrictive.

**Resolution**:
- Add peer links to create shorter paths (bypass slow parent links).
- Use Mesh mode for maximum path diversity.
- Increase `RELAY_THROTTLE_FRACTION` to allow more relay bandwidth.
- Deploy redirectors closer to relay agents to reduce latency.

### 5. Compromised Agent Containment

**Symptoms**: An agent is suspected compromised. Need to contain it.

**Procedure**:

1. **Quarantine** the agent:
   ```bash
   curl -X POST https://c2.example.com/api/mesh/quarantine \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"agent_id":"SUSPICIOUS-HOST","reason":2}'
   ```

2. **Verify quarantine** in topology — the agent should show as quarantined:
   ```bash
   curl https://c2.example.com/api/mesh/topology \
     -H "Authorization: Bearer $TOKEN"
   ```

3. **Kill switch** (if isolation is insufficient):
   ```bash
   curl -X POST https://c2.example.com/api/mesh/kill-switch \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"agent_id":"SUSPICIOUS-HOST"}'
   ```

4. **Revoke certificate** to prevent reconnection:
   ```bash
   # Certificate revocation propagates automatically through the mesh
   ```

5. **Verify** surrounding agents' key rotation status:
   - Neighbors should automatically rotate keys after quarantine.
   - Check `ListLinks` for `key_rotation_in_progress: false`.

---

## Performance Characteristics

### Overhead Per Hop

| Component | Overhead |
|-----------|----------|
| Frame header | 10 bytes (type + link_id + length) |
| Encryption overhead | 28 bytes per frame (12B nonce + 16B tag) |
| Routing latency | ~50ms typical per hop |
| Route table lookup | O(1) HashMap lookup |

### Encryption Cost

| Operation | Cost |
|-----------|------|
| ChaCha20-Poly1305 encrypt | ~0.5 µs per KiB |
| ChaCha20-Poly1305 decrypt | ~0.5 µs per KiB |
| X25519 ECDH (handshake) | ~500 µs |
| X25519 ECDH (key rotation) | ~500 µs |
| HKDF-SHA256 key derivation | ~10 µs |

### Memory Per Link

| Component | Size |
|-----------|------|
| P2pLink struct | ~1.2 KiB |
| Routing table entry | 13 bytes per route |
| Latency sample buffer | 40 bytes (10 × u32) |
| Send queue | Configurable (default 256 messages) |
| **Total per link** | **~2 KiB + queue** |

### Bandwidth Per Operation

| Operation | Bandwidth |
|-----------|-----------|
| Heartbeat (bidirectional) | ~100 bytes / 30s = ~3 B/s |
| Route update (full table, 20 routes) | ~270 bytes / 60s = ~4.5 B/s |
| Route probe (bidirectional) | ~20 bytes / probe |
| Bandwidth probe | 1–16 KiB / probe |
| Key rotation (once / 4h) | ~120 bytes one-time |
| Certificate renewal (once / 24h) | ~200 bytes one-time |

### Scaling Characteristics

| Metric | Value |
|--------|-------|
| Max agents per mesh | Limited by server capacity (tested: 500+) |
| Max hops (depth) | Theoretically unlimited; practical limit ~10 |
| Route convergence time | ~2 × ROUTE_UPDATE_INTERVAL (120s default) |
| Link establishment time | ~200ms (ECDH + HKDF) |
| Key rotation time | ~100ms round-trip |
