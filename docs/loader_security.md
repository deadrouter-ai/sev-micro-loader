# Loader Security Audit: Why Runtime Fetching Is Safe

## Overview

The Confidential Micro-Loader uses an unusual architecture: instead of packaging the server application directly into the measured boot image, it **downloads** the server at runtime from a public GitHub release. This document provides a detailed security audit of this design choice, explaining why it does not introduce vulnerabilities and how multiple independent layers prevent abuse.

## The Architecture

```mermaid
flowchart LR
    subgraph MEASURED["Measured by AMD Hardware (Immutable)"]
        LOADER["Micro-Loader Binary"]
        URL["Hardcoded URL:<br/>github.com/.../releases/latest"]
        KEY["Hardcoded Ed25519 Public Key:<br/>0x1a15f398..."]
        CA["Embedded TLS Root Certificates:<br/>Mozilla CA Store"]
    end
    subgraph RUNTIME["Downloaded at Runtime"]
        BIN["Server Binary"]
        SIG["Detached Signature"]
    end
    subgraph VERIFY["Verification Chain"]
        TLS["TLS validates GitHub identity"]
        SIGCHECK["Ed25519 validates binary authenticity"]
        HASH["SHA-384 hash recorded for attestation"]
    end
    URL -->|HTTPS| BIN
    URL -->|HTTPS| SIG
    CA --> TLS
    TLS --> BIN
    KEY --> SIGCHECK
    SIG --> SIGCHECK
    SIGCHECK -->|Pass| HASH
    SIGCHECK -->|Fail| HALT["PANIC SHUTDOWN"]
```

---

## Security Analysis

### Question 1: Can the owner point the loader to a malicious server?

**No.** The download URLs are **hardcoded in the source code** and compiled into the binary:

```rust
const BINARY_URL: &str = "https://github.com/deadrouter-ai/api-proxy-server/releases/latest/download/server";
const SIGNATURE_URL: &str = "https://github.com/deadrouter-ai/api-proxy-server/releases/latest/download/server.sig";
```

These URLs are part of the **measured binary**. Changing them would:
1. Change the compiled binary → change the CPIO hash → change the SEV-SNP measurement
2. Be visible in the public source code diff to anyone watching the repository
3. Require a new release that users would need to re-verify

**Verdict: ✅ Not a vulnerability.** The URLs cannot be changed without detection.

### Question 2: Can the owner push a backdoored server update?

**Technically possible, but immediately detectable.** Here's why this attack fails in practice:

1. **The server source code is fully public.** The binary is built from `github.com/deadrouter-ai/api-proxy-server`, which is a public repository. Every line of code is visible. Every commit is traceable.

2. **The build pipeline is public GitHub Actions.** There are no secret build steps. Anyone can fork the repo, run the same pipeline, and verify they get the same binary.

3. **The attack cannot be targeted.** A backdoored release would be served to **all users equally**. The owner cannot serve different binaries to different users because GitHub Releases are a public CDN. This makes targeted attacks impossible and mass attacks immediately visible.

4. **Users can compile and compare.** Anyone suspicious can compile the server from source, compute its SHA-384 hash, and compare it against the hash reported by the attestation endpoint. If they differ, the backdoor is exposed.

5. **The signing key provides accountability.** Only the owner can sign a release. A backdoored release is cryptographically traceable to the owner's signing key. This is a strong deterrent.

**Verdict: ✅ Mitigated by transparency.** The owner can sign a malicious release, but it would be:
- Built from public source code (auditable)
- Built by a public CI pipeline (reproducible)
- Served to everyone equally (not targetable)
- Cryptographically traceable to the owner (accountable)

**But there's an even stronger defense:** Even in the absolute worst case — the owner signs a backdoored binary and somehow tricks every auditor — the **independent attestation server on port 8080** exposes the SHA-384 hash of the running application in every attestation response. Any user can:
1. Query `GET /v1/attestation?nonce=<random>` at any time (nonce must be between 1 and 128 bytes, hex-encoded)
2. Read the `payload_sha384` field from the response
3. Compare it against the SHA-384 of the published binary on GitHub (or compile it themselves)
4. Verify the hardware-signed `report_data` by computing `SHA-512(payload_sha384_bytes || nonce_bytes)` and ensuring it matches the `report_data_hex` and the `report_data` field within the signed attestation report
5. If the hashes or verification checks fail → system integrity is compromised / backdoor detected

This makes the downloaded server **exactly as verifiable** as the loader itself from a cryptographic perspective. The attestation endpoint cannot be tampered with because:
- It is part of the **measured loader** (PID 1), not the downloaded server
- Changing it changes the SEV-SNP measurement
- The server process cannot modify PID 1 (it's a child process with no privilege over its parent)
- If the server process tries to interfere with port 8080 (e.g., crash the loader), the **entire VM immediately shuts down** — PID 1 death = kernel panic

### Question 3: Can GitHub serve a malicious binary?

**No.** Even if GitHub (or a state-level attacker that has compromised GitHub) replaces the binary on the release page, the attack fails:

1. **Ed25519 signature verification is independent of TLS.** The binary must carry a valid signature matching the hardcoded public key. GitHub does not have access to the owner's private Ed25519 signing key.

2. **The public key is hardcoded in the measured binary.** It cannot be swapped out without changing the SEV-SNP measurement:
   ```rust
   const PUBLIC_KEY_BYTES: [u8; 32] = [
       0x1a, 0x15, 0xf3, 0x98, 0x31, 0xd2, 0x7f, 0x93,
       // ... (hardcoded, immutable, measured by hardware)
   ];
   ```

3. **On signature failure, the VM shuts down instantly.** There is no fallback, no retry with different code, no degraded mode. The system calls `reboot(RB_POWER_OFF)` to immediately cut all power. No code ever executes.

**Verdict: ✅ Not a vulnerability.** GitHub cannot forge the owner's signature.

### Question 4: Can a state-level attacker compromise the TLS/CA system?

**A compromised CA allows intercepting the download, but not bypassing signature verification.**

Attack scenario: A state actor compels a Certificate Authority to issue a fraudulent certificate for `github.com`, allowing them to MITM the HTTPS connection and serve a different binary.

Defense: The Ed25519 signature is a **completely independent verification layer** that does not depend on TLS or the CA system. Even if the TLS layer is fully compromised:
- The attacker can serve a different binary ✅
- The attacker **cannot** produce a valid Ed25519 signature ❌
- The VM shuts down on the invalid signature ✅

**Verdict: ✅ Defense in depth works.** TLS is the first layer; Ed25519 is the second, independent layer.

### Question 5: What about the runtime filesystem after download?

After the binary is verified and written to disk, the loader performs a complete filesystem lockdown:

| Mount Point | Permission | Purpose |
|:---|:---|:---|
| `/run/payload` | READ-ONLY | Server binary lives here — immutable after write |
| `/tmp` | NOEXEC | Writable scratch space — but nothing can execute from here |
| `/run` | NOEXEC | Runtime directory — no executables allowed |
| `/proc`, `/sys` | NOEXEC | Kernel interfaces — standard security flags |

**After lockdown, no writable+executable filesystem exists.** This means even if the server process has a remote code execution vulnerability, the attacker:
- Cannot modify the server binary (read-only)
- Cannot drop and run a new binary (all writable dirs are noexec)
- Cannot load a kernel module (`CONFIG_MODULES=n`)
- Cannot open a shell (no shell binary exists anywhere in the filesystem)
- Cannot persist across reboot (everything is RAM-only, no disk)

### Question 6: Why not just include the server in the boot image?

Including the server in the boot image would mean:
- **Every server update changes the SEV-SNP measurement.** Users would need to re-verify after every update, which creates friction and reduces security (users stop checking).
- **The boot image becomes large and hard to audit.** The server may be millions of lines of code. The loader is ~750 lines.
- **No separation of concerns.** The measured trust anchor should be small, stable, and auditable. The application logic should be independently updatable.

With the current architecture:
- The loader (trust anchor) is tiny, stable, and rarely changes
- The server can be updated without changing the measurement
- Updates still require the owner's cryptographic signature
- The small loader is easy for anyone to audit completely

### Question 7: What if a malicious binary somehow gets through all defenses?

Even in the theoretical worst case where every defense layer fails and a malicious binary runs inside the VM, the damage is severely contained:

1. **No lateral movement.** The malicious binary runs on a READ-ONLY mount. All writable directories are NOEXEC. There is no shell, no compiler, no package manager, no SSH. The attacker cannot drop tools, cannot compile exploits, cannot open a reverse shell.

2. **Automatic detection via attestation.** The independent attestation server on port 8080 exposes the `payload_sha384` of the running binary in every response. Any user querying attestation will see a hash that doesn't match the published binary. The backdoor is caught red-handed on the very next attestation query.

3. **Cannot tamper with detection.** The attestation server is PID 1 — the most privileged process. The malicious server is a child process. It cannot:
   - Kill PID 1 (killing PID 1 causes a kernel panic → VM dies)
   - Bind to port 8080 (already bound by PID 1)
   - Modify PID 1's memory (separate process, no `ptrace` without `CAP_SYS_PTRACE` and no tools to do it)
   - Modify the attestation responses (they come from AMD hardware, not from software)

4. **Any interference = immediate shutdown.** The system is designed so that any anomaly triggers an immediate power-off:
   - Server process dies → VM shuts down
   - Attestation server fails → VM shuts down
   - Any critical operation fails → VM shuts down
   
   A malicious binary cannot operate silently. Any attempt to interfere with the system kills the entire VM, making the compromise immediately visible to monitoring.

5. **No persistence.** Everything is RAM-only. There is no disk. A reboot starts fresh from the measured boot image. The attacker gains nothing lasting.

## Summary of Defense Layers

```mermaid
flowchart TB
    DOWNLOAD["Binary Downloaded<br/>from GitHub"]
    TLS{"TLS 1.3 + PQ Crypto<br/>AES-256 + MLKEM768X25519"}
    SIG{"Ed25519 Signature<br/>Hardcoded Public Key"}
    WRITE["Write to /run/payload"]
    LOCK["Remount READ-ONLY"]
    NOEXEC["All writable mounts: NOEXEC"]
    RUN["Execute verified binary"]
    WATCH["Attestation Watchdog on port 8080<br/>Exposes payload SHA-384 continuously"]

    DOWNLOAD --> TLS
    TLS -->|"Valid cert"| SIG
    TLS -->|"Invalid cert"| HALT1["Connection fails"]
    SIG -->|"Valid signature"| WRITE
    SIG -->|"Invalid signature"| HALT2["PANIC SHUTDOWN"]
    WRITE --> LOCK --> NOEXEC --> RUN
    RUN --> WATCH
    WATCH -->|"Server dies or watchdog fails"| HALT3["PANIC SHUTDOWN"]

    style HALT1 fill:#e94560,color:#fff
    style HALT2 fill:#e94560,color:#fff
    style HALT3 fill:#e94560,color:#fff
    style TLS fill:#16213e,stroke:#0f3460,color:#eee
    style SIG fill:#16213e,stroke:#0f3460,color:#eee
    style LOCK fill:#0f3460,stroke:#e94560,color:#eee
    style NOEXEC fill:#0f3460,stroke:#e94560,color:#eee
    style WATCH fill:#533483,stroke:#e94560,color:#eee
```

| Layer | What It Stops | Independent? |
|:---|:---|:---|
| **TLS 1.3 + Post-Quantum KX** | Network interception, quantum attacks, protocol downgrade | Yes |
| **Ed25519 signature** | Tampered binaries, compromised GitHub, rogue CAs | Yes |
| **Hardcoded URLs** | Redirection to malicious servers | Yes |
| **Public source code** | Hidden backdoors by the owner | Yes |
| **Reproducible builds** | Discrepancies between source and binary | Yes |
| **Filesystem lockdown** | Post-exploitation persistence and lateral movement | Yes |
| **Attestation watchdog** | Silent compromise — exposes payload hash for continuous verification | Yes |
| **Panic shutdown** | Lingering in a degraded/compromised state — any anomaly kills the VM | Yes |
| **AMD SEV-SNP measurement** | Boot image tampering by the cloud provider | Yes |

Each layer is **independently sufficient** to stop its targeted attack class. An attacker must defeat **all layers simultaneously** to compromise the system.
