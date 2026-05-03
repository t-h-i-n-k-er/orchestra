# Redirector Deployment Guide

Complete guide for deploying Orchestra redirectors: VPS setup, TLS certificate provisioning, cover content serving, CDN integration, health monitoring, failover behavior, registration, and heartbeat management.

---

## Overview

Redirectors are lightweight proxy servers that sit between agents and the Orchestra C2 server. They forward agent traffic to the C2 server while serving legitimate cover content to any non-agent visitors. This provides:

- **IP protection** — The real C2 server IP is never exposed to the target network
- **Resilience** — Multiple redirectors provide redundancy
- **Cover traffic** — Non-agent visitors see legitimate website content
- **Domain fronting** — CDN-based redirectors mask the true destination

### Architecture

```
                    Target Network
                         │
                    ┌────▼─────┐
                    │  Agent   │  Beacons to redirector domain
                    └────┬─────┘
                         │ HTTPS
                    ┌────▼─────┐
                    │Redirector│  VPS with TLS, cover content
                    │ (VPS #1) │
                    └────┬─────┘
                         │ HTTPS (or CDN)
              ┌──────────┼──────────┐
              │                     │
         ┌────▼─────┐         ┌────▼─────┐
         │Redirector│         │ CDN Edge │  Domain fronting
         │ (VPS #2) │         │(CloudFront│
         └────┬─────┘         │ etc.)    │
              │               └────┬─────┘
              │                     │
              └──────────┬──────────┘
                         │ HTTPS (authenticated)
                    ┌────▼─────┐
                    │  C2      │  Orchestra server
                    │  Server  │  (behind firewall)
                    └──────────┘
```

---

## Quick Start

### 1. Provision a VPS

Requirements:
- Any cloud provider (AWS EC2, DigitalOcean, Linode, Vultr, etc.)
- Ubuntu 22.04+ or similar Linux distribution
- At least 1 GB RAM, 1 vCPU
- Public IP address
- Port 443 (HTTPS) open

### 2. Build the Redirector

```bash
cargo build --release -p redirector
```

The binary is at `target/release/redirector`.

### 3. Obtain TLS Certificates

**Option A: Let's Encrypt (recommended)**

```bash
# Install certbot
apt install certbot

# Obtain certificate
certbot certonly --standalone -d redirector.example.com

# Certificates are at:
# /etc/letsencrypt/live/redirector.example.com/fullchain.pem
# /etc/letsencrypt/live/redirector.example.com/privkey.pem
```

**Option B: Custom CA**

```bash
# Generate private key
openssl genrsa -out redirector.key 4096

# Generate CSR
openssl req -new -key redirector.key -out redirector.csr

# Sign with your CA
openssl x509 -req -in redirector.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out redirector.crt -days 365

# Or use a self-signed cert (testing only)
openssl req -x509 -newkey rsa:4096 -keyout redirector.key \
  -out redirector.crt -days 365 -nodes
```

### 4. Prepare Cover Content

Create a directory with legitimate website content:

```bash
mkdir -p /var/www/cover
cat > /var/www/cover/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body><h1>Welcome to our website</h1></body>
</html>
EOF
```

For best OPSEC, mirror a real website:

```bash
# Download a website for cover content (with permission)
wget --mirror --convert-links --adjust-extension \
  --page-requisites --no-parent https://example-site.com/
```

### 5. Register with Orchestra Server

Generate an authentication token:

```bash
# On the Orchestra server
orchestra-server generate-token --role redirector
# Output: rd_abc123def456...
```

### 6. Start the Redirector

```bash
./redirector \
  --listen-addr 0.0.0.0:443 \
  --c2-addr c2-server.internal:8443 \
  --profile linkedin \
  --cover-content /var/www/cover \
  --tls-cert /etc/letsencrypt/live/redirector.example.com/fullchain.pem \
  --tls-key /etc/letsencrypt/live/redirector.example.com/privkey.pem \
  --server-api https://c2-server.internal:8443/api \
  --server-token rd_abc123def456...
```

---

## CLI Reference

### `redirector`

```
Usage: redirector [OPTIONS]

Options:
  --listen-addr <ADDR>        Listen address (default: 0.0.0.0:443)
  --c2-addr <ADDR>            C2 server address (required)
  --profile <NAME>            Malleable profile name (default: "default")
  --cover-content <DIR>       Directory with cover content (default: "./static")
  --tls-cert <PATH>           TLS certificate PEM file (required)
  --tls-key <PATH>            TLS private key PEM file (required)
  --server-api <URL>          Orchestra server API URL (for registration)
  --server-token <TOKEN>      Authentication token for server
  --max-body-size <BYTES>     Maximum request body size (default: 10485760)
  --request-timeout <SECS>    Upstream request timeout (default: 30)
  --log-level <LEVEL>         Log level: trace, debug, info, warn, error (default: info)
  -h, --help                  Show help
  -V, --version               Show version
```

---

## URI Matching

The redirector uses the malleable profile's URI patterns to distinguish agent traffic from regular visitors:

### Matching Logic

```
1. Incoming HTTPS request arrives
2. Check if URI matches any pattern in profile.http_get.uri or profile.http_post.uri
3. If match → Forward to C2 server (agent traffic)
4. If no match → Serve cover content (visitor traffic)
```

### Profile URI Examples

```toml
# LinkedIn profile
[http_get]
uri = ["/voyager/api/me", "/voyager/api/messaging"]

[http_post]
uri = ["/voyager/api/events", "/voyager/api/messaging/conversations"]
```

With this profile:
- `GET /voyager/api/me` → Forwarded to C2 (agent beacon)
- `POST /voyager/api/events` → Forwarded to C2 (task result)
- `GET /index.html` → Served from cover content
- `GET /about` → Served from cover content

### Cover Content Serving

The redirector serves static files from the `--cover-content` directory:

| Request | Response |
|---------|----------|
| `GET /` | `/index.html` |
| `GET /about` | `/about.html` or `/about/index.html` |
| `GET /css/style.css` | `/css/style.css` |
| `GET /images/logo.png` | `/images/logo.png` |
| Any non-file path | `/404.html` or `404 Not Found` |

---

## Registration and Heartbeat

### Registration

When the redirector starts, it registers with the Orchestra server:

```rust
POST /api/redirector/register
Authorization: Bearer rd_abc123def456...
Content-Type: application/json

{
    "listen_addr": "203.0.113.50:443",
    "profile": "linkedin",
    "version": "1.0.0"
}
```

Response:
```json
{
    "redirector_id": "rd-uuid-1234",
    "heartbeat_interval_secs": 30
}
```

### Heartbeat

The redirector sends periodic heartbeats to the server:

```rust
POST /api/redirector/heartbeat
Authorization: Bearer rd_abc123def456...
Content-Type: application/json

{
    "redirector_id": "rd-uuid-1234",
    "active_connections": 3,
    "total_requests": 150,
    "agent_requests": 47,
    "cover_requests": 103,
    "uptime_secs": 86400,
    "last_error": null
}
```

The server uses heartbeats to:
- Track which redirectors are alive
- Provide failover ordering to agents
- Detect degraded redirectors (high error rates)

### Deregistration

When the redirector shuts down gracefully, it deregisters:

```rust
DELETE /api/redirector/rd-uuid-1234
Authorization: Bearer rd_abc123def456...
```

---

## Failover Behavior

### Agent-Side Failover

Agents receive a list of redirectors from the C2 server (via the initial profile or a redirector update command):

```rust
pub struct RedirectorConfig {
    pub address: String,           // redirector.example.com:443
    pub priority: u32,             // Lower = higher priority
    pub weight: u32,               // For weighted random selection
    pub sticky_session: bool,      // Stay on same redirector after success
    pub max_sticky: usize,         // Max requests before re-randomizing (default: 10)
}
```

### Failover Flow

```
1. Agent selects redirector (weighted random by priority)
2. Agent sends beacon to selected redirector
3. If success → Stay on this redirector (sticky session)
4. If failure:
   a. Log failure
   b. Mark redirector as degraded (exponential backoff)
   c. Select next redirector
   d. If all redirectors failed → Fall back to direct C2
5. After direct C2 succeeds:
   a. Reset backoff timers
   b. Try redirectors again from highest priority
```

### Backoff Algorithm

```rust
fn calculate_backoff(failure_count: u32, max_backoff: f64) -> f64 {
    let base: f64 = 2.0;
    let delay = base.powi(failure_count as i32);
    delay.min(max_backoff)  // Cap at max_backoff (default: 60 seconds)
}
```

| Failure Count | Backoff |
|---------------|---------|
| 1 | 2s |
| 2 | 4s |
| 3 | 8s |
| 4 | 16s |
| 5 | 32s |
| 6+ | 60s (max) |

---

## CDN Integration (Domain Fronting)

### Architecture

```
Agent ──► CDN Edge ──► Redirector ──► C2 Server
         (looks like          (domain-
          CDN traffic)         fronted)
```

### Setup with CloudFront

1. **Create CloudFront distribution**:
   - Origin: Your redirector's public IP or domain
   - Alternate domain names: Your front domain (e.g., `cdn.example.com`)
   - SSL certificate: ACM certificate for `cdn.example.com`

2. **Configure the redirector** for domain fronting:
   ```bash
   ./redirector \
     --listen-addr 0.0.0.0:443 \
     --c2-addr c2-server.internal:8443 \
     --profile cloudfront \
     --cover-content /var/www/cover \
     --tls-cert /path/to/cert.pem \
     --tls-key /path/to/key.pem
   ```

3. **Configure the agent** with the front domain:
   ```toml
   # In malleable profile
   [ssl]
   sni = "d111111abcdef8.cloudfront.net"

   [http_get]
   uri = ["/api/v1/status"]
   ```

4. **Agent connection**:
   - DNS resolves `d111111abcdef8.cloudfront.net` → CloudFront edge IP
   - Agent connects to CloudFront edge IP
   - TLS SNI: `d111111abcdef8.cloudfront.net` (looks like CDN traffic)
   - HTTP Host header: Redirector's actual domain
   - CloudFront routes to redirector based on Host header
   - Redirector forwards to C2 server

### CDN Provider Support

| Provider | Domain Fronting | Configuration |
|----------|----------------|---------------|
| CloudFront | Yes | SNI = `*.cloudfront.net`, Host = redirector domain |
| Cloudflare | Limited | Enterprise plan required for custom origins |
| Akamai | Yes | SNI = Akamai edge, Host = redirector domain |
| Azure CDN | Limited | Microsoft-managed certificates only |
| Fastly | Yes | Custom SNIs supported |

---

## Health Monitoring

### Self-Check

The redirector periodically verifies its own health:

```rust
async fn health_check(&self) -> HealthStatus {
    let checks = vec![
        self.check_tls_validity(),      // TLS cert not expired
        self.check_c2_connectivity(),    // Can reach C2 server
        self.check_cover_content(),      // Cover content directory exists
        self.check_disk_space(),         // Sufficient disk space
        self.check_memory_usage(),       // Memory within bounds
    ];

    HealthStatus {
        healthy: checks.iter().all(|c| c.is_ok()),
        checks,
        timestamp: SystemTime::now(),
    }
}
```

### Server-Side Monitoring

The Orchestra server monitors redirector health via heartbeats:

| Metric | Warning Threshold | Critical Threshold |
|--------|-------------------|-------------------|
| Heartbeat latency | >5s | >15s |
| Error rate (5min) | >5% | >20% |
| Cover request ratio | <50% | <10% |
| Uptime | <24h | Restarting frequently |

When a redirector enters critical state:
1. Server marks it as degraded
2. Agents are updated with new redirector priority
3. New agents are not assigned to the degraded redirector
4. Server alerts operators via the console

---

## TLS Configuration

### Certificate Requirements

- **Valid for the redirector domain** — The CN or SAN must match the domain agents will connect to
- **Chain must be complete** — Include intermediate certificates in the PEM file
- **RSA 2048+ or ECDSA P-256+** — Modern key sizes
- **Not expired** — The redirector checks at startup and logs warnings 30 days before expiry

### Certificate Renewal

With Let's Encrypt:
```bash
# Auto-renew with certbot
certbot renew --quiet --post-hook "systemctl reload redirector"
```

Add to crontab:
```cron
0 0 1 * * certbot renew --quiet --post-hook "systemctl reload redirector"
```

### TLS Hardening

The redirector uses these TLS settings by default:

| Setting | Value | Reason |
|---------|-------|--------|
| Min protocol | TLS 1.2 | Security baseline |
| Max protocol | TLS 1.3 | Best performance |
| Cipher suites | AEAD only | No CBC-mode ciphers |
| Certificate pinning | Optional | HSTS-like agent behavior |
| Session tickets | Disabled | Prevent session tracking |

---

## Systemd Service

Create `/etc/systemd/system/orchestra-redirector.service`:

```ini
[Unit]
Description=Orchestra Redirector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=redirector
Group=redirector
ExecStart=/usr/local/bin/redirector \
  --listen-addr 0.0.0.0:443 \
  --c2-addr c2-server.internal:8443 \
  --profile linkedin \
  --cover-content /var/www/cover \
  --tls-cert /etc/letsencrypt/live/redirector.example.com/fullchain.pem \
  --tls-key /etc/letsencrypt/live/redirector.example.com/privkey.pem \
  --server-api https://c2-server.internal:8443/api \
  --server-token %d/redirector-token
Restart=on-failure
RestartSec=10
LimitNOFILE=65535

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/log/orchestra

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
systemctl daemon-reload
systemctl enable orchestra-redirector
systemctl start orchestra-redirector
```

---

## Logging

The redirector logs to stdout (structured JSON):

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "message": "request forwarded",
  "method": "POST",
  "uri": "/voyager/api/events",
  "source_ip": "10.0.0.5",
  "upstream_status": 200,
  "latency_ms": 45,
  "profile": "linkedin"
}
```

For production, redirect to a log file:
```bash
./redirector ... 2>&1 | tee -a /var/log/orchestra/redirector.log
```

Or configure journald (when using systemd):
```bash
journalctl -u orchestra-redirector -f
```

---

## Deployment Checklist

- [ ] VPS provisioned with public IP
- [ ] DNS A record pointing to VPS IP
- [ ] TLS certificate obtained (Let's Encrypt or custom CA)
- [ ] Cover content directory populated with legitimate content
- [ ] Redirector binary deployed to VPS
- [ ] Malleable profile URI patterns configured
- [ ] C2 server address configured
- [ ] Authentication token generated on C2 server
- [ ] Systemd service created and enabled
- [ ] Firewall allows port 443 inbound
- [ ] Heartbeat registration confirmed on C2 server
- [ ] Agent beacon through redirector verified
- [ ] Cover content verified (non-matching URIs return website)
- [ ] Certificate auto-renewal configured
- [ ] Log rotation configured

---

## Troubleshooting

### Redirector Won't Start

1. **TLS certificate not found**: Verify paths with `ls -la /path/to/cert.pem`
2. **Port already in use**: Check with `ss -tlnp | grep :443`
3. **Permission denied**: Redirector needs root/CAP_NET_BIND_SERVICE for port 443

### Agents Can't Connect

1. **Firewall**: Verify port 443 is open: `nc -zv redirector.example.com 443`
2. **TLS mismatch**: Certificate domain must match agent's configured address
3. **Profile mismatch**: Ensure agent and redirector use the same profile name
4. **C2 unreachable**: Verify redirector can reach C2: `curl -k https://c2-server:8443/health`

### Cover Content Not Serving

1. **Directory exists**: `ls -la /var/www/cover/`
2. **Index file**: Ensure `index.html` exists in the directory
3. **File permissions**: Redirector process user must have read access

### High Latency

1. **Geographic distance**: Place redirectors close to target network
2. **Cover content size**: Large files slow down non-agent responses
3. **Upstream timeout**: Increase `--request-timeout` if C2 is slow

---

## See Also

- [MALLEABLE_PROFILES.md](MALLEABLE_PROFILES.md) — Profile URI patterns and transforms
- [ARCHITECTURE.md](ARCHITECTURE.md) — C2 state machine and failover
- [OPERATOR_MANUAL.md](OPERATOR_MANUAL.md) — Redirector management from operator console
