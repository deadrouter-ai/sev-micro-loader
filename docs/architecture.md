# Architecture

The Confidential Micro-Loader is a specialized `init` system designed to bootstrap a highly secure, isolated server application within an AMD SEV-SNP confidential virtual machine.

## How It Works

1. **Bare-Metal Bootstrapping**:
   The loader starts as PID 1 directly from the kernel `initramfs`. There is no traditional Linux distribution underneath (no systemd, bash, SSH, or package managers). The system consists entirely of the Linux Kernel and this single static Rust binary.

2. **Network & DNS Initialization**:
   It manually configures necessary network interfaces like loopback (`lo`). It hardcodes secure DNS resolvers (e.g., Quad9, Cloudflare) into `/etc/resolv.conf`, deliberately ignoring any DNS servers provided by the DHCP server to prevent DNS hijacking by the untrusted host hypervisor.

3. **Secure Payload Fetching**:
   The loader downloads the production application payload and its detached Ed25519 signature directly from a hardcoded, trusted URL via HTTPS. TLS root certificates (Mozilla CA store) are baked directly into the loader to avoid relying on a host-provided `/etc/ssl/certs` store, which could be tampered with.

4. **Cryptographic Verification**:
   The downloaded payload is verified against a hardcoded Ed25519 public key. If the signature doesn't match—meaning the binary was intercepted or tampered with—the boot sequence halts immediately and permanently.

5. **Filesystem Lockdown**:
   Once verified, the payload is written to a volatile `tmpfs` partition (`/run/payload`). The loader then forcefully applies a filesystem lockdown:
   - `/run/payload` is remounted as `READ-ONLY` to make the binary immutable.
   - All writable filesystems (`/tmp`, `/run`) are mounted with `NOEXEC` to prevent the execution of arbitrary scripts, shellcodes, or binaries.

6. **Process Isolation & Attestation**:
   The payload is spawned as a child process. PID 1 (the loader) remains running in the background to serve as an independent, tamper-proof hardware attestation endpoint (port 8080) and a zombie process reaper. It interfaces directly with `/dev/sev-guest` to provide cryptographically signed proofs of the VM's state, returning a payload containing the user-provided nonce and the verified payload's SHA-256 hash.
