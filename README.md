# Confidential Micro-Loader (Zero-Trust Bootloader)

A hardened, RAM-only, zero-trust initialization process (PID 1) designed specifically for AMD SEV-SNP environments. It guarantees that the workload executing inside the confidential enclave is authentic, untampered, and fully isolated.

## Table of Contents
- [What is it?](docs/architecture.md)
- [Threat Model](docs/threat_model.md)
- [Step-by-Step Guide](#step-by-step-guide)
  - [100% Reproducible Build (Recommended for Auditing)](#1-100-reproducible-build-recommended-for-auditing)
  - [Native Compilation (For Local Testing)](#2-native-compilation-for-local-testing)
  - [Compilation](#3-compilation)
  - [Verification (SEV-SNP Measurement)](#4-verification-sev-snp-measurement)
  - [Local Testing (QEMU)](#5-local-testing-qemu)

---

## Step-by-Step Guide

### 1. 100% Reproducible Build (Recommended for Auditing)

To guarantee that your locally compiled binaries produce the **exact same** SEV-SNP measurement hashes as the official GitHub Actions pipeline, you **must** use the provided Docker reproducible build script. This isolates the build in a pristine `ubuntu:24.04` environment with fixed GCC and Rust versions.

**Prerequisites:** You must have `docker` installed and running on your system.

```bash
./build_reproducible.sh
```

This single command will automatically:
1. Build a fixed Docker environment (`sev-reproducible-builder`).
2. Compile the hardened Linux kernel (`bzImage`).
3. Compile the Rust Micro-Loader (`zero_trust_os.cpio`).
4. Download the OVMF firmware and compute the final SEV-SNP measurement.

When the script finishes, it will print the exact mathematical SEV-SNP measurement that you can compare against the release!

---

### 2. Native Compilation (For Local Testing)

> **IMPORTANT:** Compiling natively on your host OS (e.g., Debian, Fedora, or newer Ubuntu) will result in different binaries and hashes due to compiler toolchain differences. **Do not use native compilation for verifying official releases.**

**Prerequisites**

First, install the necessary system dependencies (Debian/Ubuntu example):

```bash
sudo apt update
sudo apt install -y build-essential flex bison libssl-dev libelf-dev wget rpm2cpio cpio jq
```

Install Rust and the required `musl` target for static compilation:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup target add x86_64-unknown-linux-musl
```

### 3. Compilation

**IMPORTANT:** If you intend to compute SEV-SNP measurements for verification, you must compile from the **Latest Release** rather than the active `main` branch. Active code changes frequently, which will result in different measurements from the official release!

1. **Compile the hardened Linux kernel:**
   ```bash
   chmod +x build_kernel.sh
   ./build_kernel.sh
   ```

2. **Compile the Micro-Loader (Deterministically):**
   To ensure the resulting binary has the exact same hash across different computers (reproducible build), we strip the absolute paths using `RUSTFLAGS`:
   ```bash
   RUSTFLAGS="--remap-path-prefix $(pwd)=/workspace" cargo build --release --target x86_64-unknown-linux-musl
   ```

3. **Create the ephemeral initramfs (rootfs) deterministically:**
   To guarantee the `cpio` archive produces the exact same hash every time, we must zero out the timestamps of the files and use `cpio`'s reproducible flag:
   ```bash
   # Create an ephemeral directory architecture
   mkdir -p rootfs/proc rootfs/sys rootfs/dev rootfs/tmp

   # Copy your compiled binary straight into the execution root under the name 'init'
   cp target/x86_64-unknown-linux-musl/release/sev-micro-loader rootfs/init

   # Zero out the timestamps of the rootfs files so the archive hash is identical everywhere
   find rootfs -exec touch -h -d @0 {} +

   # Create the reproducible initramfs
   cd rootfs
   find . -mindepth 1 | LC_ALL=C sort | cpio -o -H newc -R 0:0 --reproducible > ../zero_trust_os.cpio
   cd ..
   ```

At this point, you have two paths: compute the SEV-SNP measurement for auditing, or run it locally in QEMU.

### 4. Verification (SEV-SNP Measurement)

To verify the integrity of the enclave natively, you can compute the expected SEV-SNP measurement offline and compare it against the live attestation report.

1. **Clone the measurement utility:**
   ```bash
   git clone https://github.com/virtee/sev-snp-measure.git
   cd sev-snp-measure
   ```

2. **Download and verify the OVMF firmware:**
   We use an audited build of OVMF. Download and extract it:
   ```bash
   wget https://download.rockylinux.org/pub/rocky/10.1/devel/x86_64/os/Packages/e/edk2-ovmf-20250523-2.el10.noarch.rpm
   rpm2cpio edk2-ovmf-20250523-2.el10.noarch.rpm | cpio -idmv
   ```

   **Verify the firmware hash:**
   ```bash
   EXPECTED_HASH="950daf793754f7a8bd85b716d2ebf77b96d49724671a2ab12cf3a9607f1aa8fe"
   ACTUAL_HASH=$(sha256sum usr/share/edk2/ovmf/OVMF.amdsev.fd | awk '{print $1}')
   if [ "$EXPECTED_HASH" = "$ACTUAL_HASH" ]; then echo "✅ OVMF Hash Match!"; else echo "❌ Hash Mismatch!"; fi
   ```

3. **Compute the measurement:**
   *(Ensure paths to your kernel and initrd are correct relative to your current directory)*
   ```bash
   ./sev-snp-measure.py \
       --mode snp \
       --vcpus=2 \
       --vcpu-type=EPYC-v3 \
       --ovmf=./usr/share/edk2/ovmf/OVMF.amdsev.fd \
       --kernel=../linux-6.12.91/arch/x86/boot/bzImage \
       --initrd=../zero_trust_os.cpio \
       --append="console=ttyS0 ip=dhcp"
   ```

This will output a raw hexadecimal measurement (e.g., `0409cb2e91890852f7d71e4c605d023d27fe0f7e97ffa1c34067e0957a6ebd85749485b73127f24ba112ba5c2559e306`). You compare this value against the measurement provided by the server's live attestation to ensure the executing code is exactly what you audited.

### 5. Local Testing (QEMU)

You can run the environment locally using QEMU to test functionality. 

1. **Run the VM:**
   ```bash
   qemu-system-x86_64 \
     -kernel linux-6.12.91/arch/x86/boot/bzImage \
     -initrd zero_trust_os.cpio \
     -m 1024 \
     -nographic \
     -no-reboot \
     -append "console=ttyS0 ip=dhcp" \
     -netdev user,id=net0,hostfwd=tcp::8080-:8080 \
     -device virtio-net-pci,netdev=net0
   ```

2. **Test the Attestation Endpoint:**
   From another terminal, fetch an attestation report:
   ```bash
   curl -s "http://localhost:8080/v1/attestation?nonce=$(openssl rand -hex 32)" | jq
   ```

   *Note: Unless you are running on an AMD EPYC 7003 series processor (or newer) with SEV-SNP enabled, the hardware attestation will fail with a simulated error. This is normal and expected for local testing:*
   ```json
   {
     "error": "snp_unavailable",
     "message": "SEV-SNP device not available (/dev/sev-guest not found)",
     "payload_sha256": "417146051425dd1a39060efb8d3541f611727edfddfc7bd94866694e3d76de41",
     "nonce": "353b8ba65d3a3130b1fd2c8ed138f6798bce7d1c85c6194e9f184878cbb118e5"
   }
   ```
