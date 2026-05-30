# Threat Model

The Confidential Micro-Loader operates under a strict threat model tailored for Confidential Computing (specifically AMD SEV-SNP). We assume the physical host machine, the hypervisor, and the network infrastructure are entirely untrusted and potentially malicious.

## Untrusted Entities
1. **The Cloud Provider (Hypervisor/Host)**: Can inspect network traffic, manipulate the VM's disk, alter DHCP/DNS responses, and attempt to inject code into the boot process.
2. **Network Intermediaries**: Can attempt to spoof or alter DNS, Man-in-the-Middle (MitM) HTTP(S) traffic, or blackhole connections.
3. **The Developer/Provider (Malicious Updates)**: The threat model explicitly guards against malicious updates by the software provider. Consumers can audit the exact open-source bootloader and kernel, compute the expected SEV-SNP measurement, and mathematically verify that no secret backdoors were injected during compilation.

## Defenses & Mitigations

| Threat | Mitigation |
| :--- | :--- |
| **Boot Image Tampering** | The entire bootloader and kernel are measured by the AMD Secure Processor. Modifications to the `initramfs` or kernel will alter the SEV-SNP measurement, causing hardware attestation failure. |
| **DNS Hijacking** | DHCP-provided DNS servers are explicitly ignored. Trusted public resolvers (e.g., Quad9, Cloudflare) are hardcoded into `/etc/resolv.conf`. |
| **TLS/MitM Attacks** | The loader uses an embedded, pinned Mozilla root certificate store baked into the binary. It does not rely on host-provided certificate authorities, making TLS interception impossible without breaking the connection. |
| **Payload Tampering** | The downloaded application must have a valid Ed25519 signature matching the hardcoded public key in the measured bootloader. |
| **Runtime Code Injection** | The loader aggressively locks down the filesystem. The application binary is hosted on a `READ-ONLY` mount (`/run/payload`), and all writable directories (`/tmp`, `/run`) are mounted `NOEXEC`. |
| **SSH / Backdoors** | There is no SSH daemon, shell, or interactive login capability. The attack surface is restricted strictly to the payload application and the attestation endpoint. |
