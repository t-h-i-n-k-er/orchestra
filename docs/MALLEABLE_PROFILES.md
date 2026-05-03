# Malleable Profiles — Exhaustive Reference

Complete reference for Orchestra's malleable C2 profile system. Every TOML key, every enum value, transform algorithms, encoding examples, and troubleshooting.

---

## Overview

Malleable profiles control every aspect of the agent's network communication:

- **HTTP/S**: URI paths, headers, User-Agent, request/response transforms, data delivery methods
- **DNS**: Beacon patterns, task retrieval, data exfiltration, encoding schemes
- **SSL/TLS**: Certificate pinning, JA3 fingerprinting, SNI customization
- **Timing**: Sleep intervals, jitter, working hours, kill dates

Profiles are loaded from TOML files in the `profiles/` directory. The server watches this directory for changes and hot-reloads without restart.

---

## Profile File Structure

A profile is a TOML file with the following top-level sections:

```toml
[profile]           # Metadata
[global]            # Global settings (UA, timing)
[ssl]               # TLS configuration
[http_get]          # HTTP GET transaction (beacon)
[http_get.headers]  # GET request headers
[http_get.metadata] # GET data delivery (agent → server)
[http_get.client]   # GET client-side transforms
[http_get.server]   # GET server-side transforms
[http_post]         # HTTP POST transaction (task results)
[http_post.headers] # POST request headers
[http_post.output]  # POST data delivery (agent → server)
[http_post.client]  # POST client-side transforms
[http_post.server]  # POST server-side transforms
[dns]               # DNS C2 configuration
[dns.headers]       # DNS-over-HTTPS configuration
```

---

## Section Reference

### `[profile]` — Metadata

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `name` | string | yes | `"default"` | Profile identifier used in build and server configuration |
| `author` | string | no | `""` | Author attribution |
| `description` | string | no | `""` | Human-readable description |

Example:
```toml
[profile]
name = "linkedin"
author = "red-team"
description = "LinkedIn API traffic mimic"
```

---

### `[global]` — Global Settings

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `user_agent` | string | no | Chrome 125 UA | HTTP User-Agent for all requests |
| `jitter` | u8 (0–100) | no | `0` | Percentage of random jitter applied to sleep interval |
| `sleep_time` | u64 | no | `60` | Base sleep interval in seconds between beacons |
| `dns_idle` | string | no | `"0.0.0.0"` | IP address returned when no task data (DNS beacon) |
| `dns_sleep` | u64 | no | `0` | Additional delay between DNS queries (milliseconds) |

**User-Agent Selection Guide:**

| Scenario | Recommended UA |
|----------|---------------|
| General browsing | Chrome on Windows 10/11 |
| Enterprise network | Chrome with corporate build tag |
| API traffic | Custom UA matching the target API |
| Mobile | Safari or Chrome mobile UA |
| Legacy | IE11 or Edge Legacy |

Example:
```toml
[global]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
jitter = 37
sleep_time = 60
```

---

### `[ssl]` — TLS Configuration

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `enabled` | bool | no | `true` | Enable TLS for all communications |
| `cert_pin` | string | no | `""` | SHA-256 hex fingerprint of expected server certificate |
| `ja3_fingerprint` | string | no | `""` | Target JA3 fingerprint for TLS Client Hello |
| `sni` | string | no | `""` | Custom SNI hostname (for domain fronting) |

**Certificate Pinning:**

Generate a certificate fingerprint:
```bash
openssl x509 -in server.crt -fingerprint -sha256 -noout
# SHA256 Fingerprint=AA:BB:CC:DD:...
```

Use in profile (hex, no colons, lowercase):
```toml
[ssl]
cert_pin = "aabbccdd..."
```

**JA3 Fingerprint:**

The JA3 fingerprint is a 32-character MD5 hash of the TLS Client Hello parameters. Setting this value configures the agent to mimic a specific client's TLS fingerprint. Common JA3 values:

| Client | JA3 |
|--------|-----|
| Chrome 125 (Win10) | `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0` |
| Firefox 125 (Win10) | `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0` |

---

### `[http_get]` — HTTP GET Transaction

Controls how the agent sends beacon requests (checking for new tasks).

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `uri` | string[] | yes | `[]` | List of URI paths; one is randomly selected per request |
| `verb` | string | no | `"GET"` | HTTP method (must be `"GET"` for this section) |

Example:
```toml
[http_get]
uri = ["/api/v1/status", "/api/v1/health", "/api/v2/check"]
verb = "GET"
```

#### `[http_get.headers]`

HTTP headers sent with every GET request:

```toml
[http_get.headers]
Accept = "application/json"
Connection = "keep-alive"
Cache-Control = "no-cache"
Pragma = "no-cache"
```

#### `[http_get.metadata]`

Controls how the agent sends its beacon data (session ID, capabilities) to the server in GET requests.

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `delivery` | string | no | `"Cookie"` | Delivery method for metadata |
| `key` | string | no | `"session"` | Header/Cookie/URI key name |
| `transform` | string | no | `"Base64"` | Transform applied before delivery |

**Delivery methods:**

| Method | Data Location | Example |
|--------|---------------|---------|
| `Cookie` | `Cookie` header | `Cookie: session=<base64_data>` |
| `UriAppend` | Appended to URI | `/api/v1/status/<base64_data>` |
| `Header` | Custom header | `X-Custom: <base64_data>` |
| `Body` | HTTP body | Body contains `<base64_data>` |

#### `[http_get.client]`

Transforms applied to **outgoing** data (agent → server) in GET requests:

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `prepend` | string | no | `""` | Prepend to data before encoding |
| `append` | string | no | `""` | Append to data after encoding |
| `transform` | string | no | `"None"` | Encoding transform |
| `mask_stride` | u32 | no | `0` | XOR stride for Mask transform |

#### `[http_get.server]`

Transforms applied to **incoming** data (server → agent) in GET responses:

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `prepend` | string | no | `""` | Prepend to data before decoding |
| `append` | string | no | `""` | Append to data after decoding |
| `transform` | string | no | `"None"` | Encoding transform |
| `mask_stride` | u32 | no | `0` | XOR stride for Mask transform |

---

### `[http_post]` — HTTP POST Transaction

Controls how the agent sends task results back to the server.

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `uri` | string[] | yes | `[]` | List of URI paths; one is randomly selected per request |
| `verb` | string | no | `"POST"` | HTTP method (must be `"POST"` for this section) |

#### `[http_post.headers]`

```toml
[http_post.headers]
Content-Type = "application/json"
Accept = "application/json"
```

#### `[http_post.output]`

Controls how the agent sends task result data in POST requests.

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `delivery` | string | no | `"Body"` | Delivery method for output data |
| `key` | string | no | `"session"` | Header/Cookie key (when delivery is Header or Cookie) |
| `transform` | string | no | `"Base64"` | Transform applied before delivery |

#### `[http_post.client]`

Transforms applied to outgoing task result data:

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `prepend` | string | no | `""` | Prepend to data before encoding |
| `append` | string | no | `""` | Append to data after encoding |
| `transform` | string | no | `"None"` | Encoding transform |
| `mask_stride` | u32 | no | `0` | XOR stride for Mask transform |

#### `[http_post.server]`

Transforms applied to incoming data in POST responses ( acknowledgments from server):

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `prepend` | string | no | `""` | Prepend to data before decoding |
| `append` | string | no | `""` | Append to data after decoding |
| `transform` | string | no | `"None"` | Encoding transform |

---

### `[dns]` — DNS C2 Configuration

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `enabled` | bool | no | `false` | Enable DNS C2 channel |
| `beacon` | string | no | `""` | Beacon query pattern (replaces `{DATA}` with encoded data) |
| `get_A` | string | no | `""` | Task retrieval A record query pattern |
| `get_TXT` | string | no | `""` | Task retrieval TXT record query pattern |
| `post` | string | no | `""` | Data exfiltration query pattern |
| `max_txt_size` | u32 | no | `252` | Maximum TXT record payload size (bytes) |
| `dns_suffix` | string | no | `""` | DNS suffix domain |
| `encoding` | string | no | `"hex"` | Data encoding for DNS queries |

**Encoding options:**

| Encoding | Character Set | Max Efficiency | Notes |
|----------|---------------|----------------|-------|
| `hex` | `0-9a-f` | 50% | Simple hex encoding |
| `base32` | `A-Z2-7=` | 62.5% | Case-insensitive DNS-safe |
| `base64url` | `A-Za-z0-9-` | 75% | URL-safe Base64 (no `=` padding) |

#### `[dns.headers]` — DoH Configuration

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `doh_server` | string | no | `"https://dns.google/dns-query"` | DNS-over-HTTPS resolver URL |
| `doh_method` | string | no | `"POST"` | HTTP method for DoH queries |

**Supported DoH servers:**

| Provider | URL |
|----------|-----|
| Google | `https://dns.google/dns-query` |
| Cloudflare | `https://cloudflare-dns.com/dns-query` |
| Quad9 | `https://dns.quad9.net/dns-query` |

Example DNS configuration:
```toml
[dns]
enabled = true
beacon = "cdn.{DATA}.example.com"
get_A = "a.{DATA}.example.com"
get_TXT = "txt.{DATA}.example.com"
post = "data.{DATA}.example.com"
dns_suffix = "example.com"
encoding = "base64url"

[dns.headers]
doh_server = "https://dns.google/dns-query"
doh_method = "POST"
```

---

## Transform Types — Deep Dive

### None

Identity transform — no encoding applied.

```
Input:  48 65 6c 6c 6f
Output: 48 65 6c 6c 6f
```

### Base64

Standard Base64 encoding with `+`, `/`, and `=` padding.

```
Input:  Hello
Output: SGVsbG8=
```

### Base64Url

URL-safe Base64 with `-`, `_`, no padding.

```
Input:  Hello
Output: SGVsbG8
```

### Mask

XOR with a rotating key. The `mask_stride` parameter controls how many bytes each key byte covers before advancing.

```
Key:    [0xAA, 0xBB, 0xCC]
Stride: 4  (each key byte covers 4 plaintext bytes)

Input:  48 65 6C 6C 6F 5D 72 6C 64
Key:    AA AA AA AA BB BB BB BB CC
Output: E2 CF C6 C6 D4 E6 C9 D6 68
```

Mask is decoded by XORing with the same key.

### Netbios

NetBIOS encoding maps each hex nibble to a character in the range `A`–`P` (uppercase):

```
0 → A    4 → E    8 → I    C → M
1 → B    5 → F    9 → J    D → N
2 → C    6 → G    A → K    E → O
3 → D    7 → H    B → L    F → P
```

Each byte is encoded as two characters (high nibble first):

```
Input:  48 (0x48)
Output: EJ  (E=4, J=8)

Input:  Hello (48 65 6C 6C 6F)
Output: EJGLMMGLP
```

### NetbiosU

Same as Netbios but lowercase (`a`–`p`):

```
Input:  Hello (48 65 6C 6C 6F)
Output: ejglmmglp
```

---

## Data Flow Examples

### GET Beacon with Cookie Delivery

Agent wants to send metadata `{"id":"abc","ts":12345}` to server:

1. **Serialize**: `bincode({"id":"abc","ts":12345})` → raw bytes
2. **Encrypt**: AES-256-GCM encrypt → ciphertext
3. **Transform (client)**: Prepend `JSESSIONID=ajax:1234;` → `JSESSIONID=ajax:1234;<ciphertext>`
4. **Transform (client)**: Append `;` → `JSESSIONID=ajax:1234;<ciphertext>;`
5. **Transform (metadata)**: Base64 encode the whole string
6. **Deliver**: `Cookie: li_at=<base64_encoded_data>`
7. **HTTP GET**: `GET /voyager/api/me HTTP/1.1` with `Cookie` header

Server receives:
1. **Extract**: Cookie `li_at` value
2. **Transform (metadata)**: Base64 decode
3. **Transform (server)**: Strip prepend `JSESSIONID=ajax:1234;` and append `;`
4. **Decrypt**: AES-256-GCM decrypt → original metadata

### POST Task Result with Body Delivery

Agent wants to send task result `{"output":"file contents..."}`:

1. **Serialize**: `bincode({"output":"file contents..."})` → raw bytes
2. **Encrypt**: AES-256-GCM encrypt → ciphertext
3. **Transform (client)**: Prepend `{"csrfToken":"...","data":"` → `{"csrfToken":"...","data":"<ciphertext>`
4. **Transform (client)**: Append `"}` → `{"csrfToken":"...","data":"<ciphertext>"}`
5. **Transform (output)**: Base64 encode
6. **Deliver**: HTTP body
7. **HTTP POST**: `POST /voyager/api/events HTTP/1.1` with body

### DNS Beacon with Base64URL Encoding

Agent wants to send beacon `abc123`:

1. **Encrypt**: AES-256-GCM encrypt → ciphertext (binary)
2. **Encode**: base64url encode → `YWJjMTIz`
3. **Query**: `cdn.YWJjMTIz.example.com` A record lookup

Server receives:
1. **Extract**: Subdomain `YWJjMTIz` from query
2. **Decode**: base64url decode → ciphertext
3. **Decrypt**: AES-256-GCM decrypt → original data

---

## Profile Validation

The server validates profiles on load. Common validation errors:

| Error | Cause | Fix |
|-------|-------|-----|
| `missing required field: uri` | `[http_get]` or `[http_post]` has no `uri` | Add at least one URI |
| `invalid transform: XYZ` | Unknown transform name | Use: None, Base64, Base64Url, Mask, Netbios, NetbiosU |
| `invalid delivery: XYZ` | Unknown delivery method | Use: Cookie, UriAppend, Header, Body |
| `mask_stride requires Mask transform` | `mask_stride` set without `transform = "Mask"` | Set `transform = "Mask"` or remove `mask_stride` |
| `dns.enabled but no dns_suffix` | DNS enabled without suffix | Add `dns_suffix` |
| `invalid encoding: XYZ` | Unknown DNS encoding | Use: hex, base32, base64url |
| `empty uri list` | `uri` array is empty | Add at least one URI string |

### Validation Command

```bash
orchestra-server validate-profile --path profiles/my-profile.toml
```

---

## Multi-Profile Server

The Orchestra server can serve multiple profiles simultaneously:

1. Place multiple `.toml` files in the `profiles/` directory
2. Each profile's `[profile].name` must be unique
3. The server loads all profiles at startup
4. Agents are assigned a profile at build time
5. Hot-reload detects new/changed/removed profiles

```
profiles/
├── linkedin.toml
├── cloudfront.toml
├── teams.toml
└── default.toml
```

---

## Troubleshooting

### Profile Not Loading

1. Check TOML syntax: `tomlq . profiles/my-profile.toml`
2. Verify all required fields are present
3. Check server logs for validation errors
4. Run `orchestra-server validate-profile --path profiles/my-profile.toml`

### Agent Not Using Profile

1. Verify the profile was loaded by the server: check server logs at startup
2. Verify the agent was built with the correct profile
3. Check that `http-transport` feature is enabled
4. Verify the server URL matches the agent's configured endpoint

### Transforms Producing Garbled Data

1. Ensure client and server transforms are inverse operations
2. If using `prepend`/`append`, the server must strip exactly what the client adds
3. Base64 encoding adds padding (`=`) that may need accounting for
4. Mask transform requires the same `mask_stride` on both sides

### DNS Queries Not Working

1. Verify DNS suffix is a domain you control
2. Verify the DNS server is configured to resolve queries for the suffix
3. Check that `encoding` is set correctly
4. Verify DoH server URL is accessible from the agent's network
5. Check max_txt_size isn't exceeding DNS limits

### Certificate Pinning Failures

1. Regenerate the fingerprint: `openssl x509 -in cert.pem -fingerprint -sha256 -noout`
2. Remove colons and convert to lowercase
3. Verify the certificate hasn't changed since the fingerprint was generated
4. Check that the full certificate chain is being served

---

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) — Wire protocol and C2 state machine
- [REDIRECTOR_GUIDE.md](REDIRECTOR_GUIDE.md) — Redirector deployment with malleable profiles
- [OPERATOR_MANUAL.md](OPERATOR_MANUAL.md) — Profile management from the operator console
