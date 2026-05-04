# Anti-Forensic Capabilities

This document covers Orchestra's anti-forensic subsystem, including evidence removal, timestamp manipulation, and operational security recommendations for minimizing detection risk.

---

## Forensic Cleanup Pipeline

The forensic cleanup module (`forensic-cleanup` feature) removes evidence of agent execution from common forensic artifacts. The cleanup pipeline runs automatically at initialization and can be triggered on-demand via the `forensic_cleanup` command.

### Pipeline Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Forensic Cleanup Pipeline                       │
│                                                                      │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐            │
│  │ Prefetch     │──▶│ MFT Timestamp│──▶│ USN Journal  │            │
│  │ Removal      │   │ Sync         │   │ Cleanup      │            │
│  └──────────────┘   └──────────────┘   └──────────────┘            │
│         │                  │                    │                     │
│         ▼                  ▼                    ▼                     │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐            │
│  │ Disable      │   │ $LogFile     │   │ Memory       │            │
│  │ Prefetch Svc │   │ Cleanup      │   │ Hygiene      │            │
│  └──────────────┘   └──────────────┘   └──────────────┘            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Stage 1: Prefetch Evidence Removal

Windows Prefetch (`%SystemRoot%\Prefetch\*.pf`) records application execution history including:
- Executable name and path
- Run count and timestamps
- Files and directories accessed
- Network resources accessed

**Cleanup Actions**:

1. **Enumerate Prefetch Files**: Scans `C:\Windows\Prefetch\` for any `.pf` files referencing:
   - The agent binary name
   - The launcher binary name
   - The sacrificial process (spawnto)
   - Any executed modules or tools

2. **Patch Prefetch Data**: For each matching `.pf` file:
   - Overwrites the executable name and path with null bytes
   - Zeros the run count
   - Clears the timestamps array
   - Invalidates the file reference chain
   - Recomputes the prefetch header hash for consistency

3. **Delete if Necessary**: If patching would leave forensic artifacts, the file is deleted entirely.

4. **Disable Prefetch Service** (optional): When `disable_prefetch_service` is `true`:
   - Sets `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher` to `0`
   - Stops the `SysMain` service (which manages prefetch)
   - Prevents future prefetch evidence collection

### Stage 2: MFT Timestamp Synchronization

The Master File Table (MFT) stores timestamps for every file on an NTFS volume:
- **Creation Time** (`B`)
- **Modification Time** (`M`)
- **Access Time** (`A`)
- **Entry Modified Time** (`MFT Modified`)

**Cleanup Actions**:

1. **Record Baseline**: Before any file operations, capture timestamps of affected files
2. **Timestomp**: After execution, restore original timestamps via `NtSetInformationFile` with `FileBasicInformation` class
3. **MFT Entry Zeroing**: For deleted files, zero the MFT entry to prevent timestamp recovery from residual data

### Stage 3: USN Journal Cleanup

The Update Sequence Number (USN) Journal is an NTFS log that records file system changes:
- File creation, deletion, modification, and rename operations
- Used by forensic tools to reconstruct file system activity

**Cleanup Actions**:

1. **Enumerate Entries**: Query the USN journal for entries referencing agent-related files
2. **Delete Specific Entries**: Use `FSCTL_DELETE_USN_JOURNAL` with `USN_DELETE_FLAG_NOTIFY` to selectively remove entries
3. **Nuclear Option**: If selective deletion is insufficient, delete the entire USN journal:
   ```
   FSCTL_DELETE_USN_JOURNAL with USN_DELETE_FLAG_DELETE
   ```
   This creates a new, clean journal from the current point forward.

### Stage 4: $LogFile Cleanup

NTFS maintains a `$LogFile` that records all transaction-like operations:
- File creation, modification, deletion
- Metadata changes
- Journaling data for crash recovery

**Cleanup Actions**:

1. **Identify Relevant Records**: Scan `$LogFile` pages for records referencing agent files
2. **Overwrite Records**: Replace matching records with zero-filled data
3. **Recalculate Checksum**: Update page checksums to prevent corruption detection

### Stage 5: Memory Hygiene

After all disk-based cleanup, memory hygiene ensures no forensic evidence remains in RAM:

1. **Zero Sensitive Buffers**: All temporary buffers used during cleanup are zeroed with `SecureZeroMemory`
2. **Free Temporary Allocations**: Any memory allocated for cleanup operations is freed
3. **Flush Buffers**: Call `NtFlushBuffersFile` to ensure all changes are committed to disk

---

## Detection Risk Assessment

### Low-Risk Operations

| Operation | Forensic Artifact | Risk Level | Notes |
|-----------|-------------------|------------|-------|
| Prefetch patch | `.pf` file modification | Low | Prefetch is rarely monitored in real-time |
| MFT timestomp | MFT entry modification | Low | Common in legitimate software |
| Memory hygiene | RAM state | Very Low | No persistent artifact |
| PEB unlinking | Process module list | Low | Only visible via VAD walk |

### Medium-Risk Operations

| Operation | Forensic Artifact | Risk Level | Notes |
|-----------|-------------------|------------|-------|
| Prefetch deletion | Missing `.pf` files | Medium | Gaps in prefetch history are notable |
| USN journal cleanup | USN journal modification | Medium | Journal deletion is a known IOC |
| Prefetch service disable | Registry modification | Medium | Detectable via registry monitoring |
| Token impersonation | Handle table entries | Medium | Unusual primary tokens in handle table |

### High-Risk Operations

| Operation | Forensic Artifact | Risk Level | Notes |
|-----------|-------------------|------------|-------|
| Kernel callback overwrite | Driver load + kernel memory write | High | BYOVD is heavily monitored |
| LSASS memory read | Process handle to LSASS | High | LSASS access is a top IOC |
| $LogFile cleanup | NTFS metadata corruption | High | $LogFile modification can trigger FS checks |
| SSP installation | Registry + LSASS module load | High | SSP changes are closely monitored |

---

## Operational Security Recommendations

### Pre-Deployment

1. **Profile Selection**: Choose a malleable profile that matches the target network's traffic patterns
2. **Feature Minimization**: Only enable features needed for the operation — every feature increases the attack surface
3. **Build Diversification**: Use `self-reencode` and `junk_macro` to generate unique builds for each target
4. **Cover Traffic**: Deploy redirectors with legitimate cover content before agent deployment

### During Operation

1. **Jitter Configuration**: Set jitter to 20–40% to avoid predictable beacon timing
2. **Sleep Time**: Use realistic sleep intervals (>30s) matching legitimate application behavior
3. **Injection Target**: Choose a sacrificial process that matches the operational context (e.g., `svchost.exe` for service context, `explorer.exe` for user context)
4. **Token Discipline**: Use `rev2self` after token operations; don't hold stolen tokens longer than necessary
5. **LSASS Access**: Minimize the number of LSASS reads; cache harvested credentials in memory
6. **Prefetch Service**: Leave the Prefetch service enabled if disabling it would be anomalous for the environment
7. **USN Journal**: Only delete the entire USN journal as a last resort — selective entry removal is preferred

### Post-Operation

1. **Full Cleanup**: Run `forensic_cleanup` before agent termination
2. **Process Termination**: Exit cleanly rather than being killed — clean exit allows full cleanup
3. **Evidence Verification**: Verify that all prefetch, USN, and MFT artifacts have been cleaned
4. **Persistence Removal**: If persistence was established, ensure it's removed before departure

### EDR-Specific Considerations

#### Defender for Endpoint
- Prefetch cleanup is generally safe — MDE does not monitor prefetch in real-time
- ETW patching is effective — MDE relies heavily on ETW for telemetry
- Sleep obfuscation defeats most memory scanning

#### CrowdStrike Falcon
- Falcon performs frequent stack walks — stack spoofing is essential
- Kernel callbacks are Falcon's primary collection mechanism — BYOVD is high-value but high-risk
- Falcon monitors SSP changes closely — LSA Whisperer requires careful timing

#### SentinelOne
- SentinelOne performs behavioral analysis on sleep patterns — use Cronus over Ekko
- Process hollowing detection is strong — prefer transacted hollowing or delayed module stomp
- Token impersonation detection via handle table analysis — minimize stolen token count

#### Carbon Black
- CB relies on kernel callbacks for process monitoring — similar BYOVD considerations as Falcon
- CB performs binary reputation checks — `self-reencode` is essential for avoiding hash-based detection
- Memory scanning is less aggressive than other EDRs — Evanesco may not be necessary

---

## Anti-Forensic Feature Summary

| Feature | Feature Flag | Artifacts Cleaned | Risk Level |
|---------|-------------|-------------------|------------|
| **Prefetch Removal** | `forensic-cleanup` | `.pf` files, PrefetchParameters registry | Low–Medium |
| **MFT Timestamp Sync** | `forensic-cleanup` | MFT $STANDARD_INFORMATION timestamps | Low |
| **USN Journal Cleanup** | `forensic-cleanup` | USN journal entries | Medium |
| **$LogFile Cleanup** | `forensic-cleanup` | NTFS $LogFile records | High |
| **PEB Unlinking** | (default) | PEB_LDR_DATA module entries | Low |
| **Thread Start Scrub** | (default) | Thread start addresses | Low |
| **Handle Table Scrub** | (default) | Suspicious handle entries | Low |
| **Memory Hygiene** | (default) | In-memory forensic artifacts | Very Low |
| **Sleep Obfuscation** | `sleep-obfuscation` | Memory content during sleep | Low |
| **Evanesco** | `evanesco` | Memory content at all times | Low |
| **String Encryption** | `string_crypt` | Compile-time string artifacts | Very Low |
| **Binary Diversification** | `junk_macro` + `optimizer` | Binary signature IoCs | Very Low |
| **Self-Reencoding** | `self-reencode` | Per-build .text signatures | Very Low |
