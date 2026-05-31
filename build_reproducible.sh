#!/bin/bash
set -e

if ! docker info >/dev/null 2>&1; then
    if sudo docker info >/dev/null 2>&1; then
        DOCKER="sudo docker"
    else
        echo "Docker is not installed or running."
        exit 1
    fi
else
    DOCKER="docker"
fi

# Build the Docker image specifically for our reproducibility
echo "Building reproducible Docker image..."
$DOCKER build --network host -t sev-reproducible-builder -f Dockerfile.reproducible .

# Run the build process inside the container
# IMPORTANT: We do NOT mount $HOME/.cargo into the container. The Docker image
# has Rust 1.95.0 installed at a fixed version. Mounting the host's .cargo would
# override this with whatever the host has, breaking reproducibility.
echo "Running build inside isolated container..."
mkdir -p "$HOME/.cache/ccache"
$DOCKER run --rm --network host \
    -v "$(pwd):/workspace" \
    -v "$HOME/.cache/ccache:/root/.cache/ccache" \
    -w /workspace \
    sev-reproducible-builder \
    /bin/bash -c '
        set -e
        # 1. Build Kernel
        export PATH="/usr/lib/ccache:$PATH"
        export CCACHE_DIR=/root/.cache/ccache
        ccache -M 2G
        chmod +x build_kernel.sh
        ./build_kernel.sh
        ccache -s

        # 2. Build Rust Bootloader
        # Use a container-local target directory to avoid contamination from
        # any host target/ artifacts that were mounted in via the workspace.
        export CARGO_TARGET_DIR=/tmp/cargo-target
        CC_x86_64_unknown_linux_musl=musl-gcc \
            RUSTFLAGS="--remap-path-prefix $(pwd)=/workspace" \
            cargo build --locked --release --target x86_64-unknown-linux-musl

        # 3. Create Initramfs
        rm -rf rootfs zero_trust_os.cpio
        mkdir -p rootfs/proc rootfs/sys rootfs/dev rootfs/tmp
        cp /tmp/cargo-target/x86_64-unknown-linux-musl/release/sev-micro-loader rootfs/init
        find rootfs -exec touch -h -d @0 {} +
        cd rootfs
        find . -mindepth 1 | LC_ALL=C sort | cpio -o -H newc -R 0:0 --reproducible > ../zero_trust_os.cpio
        cd ..

        # 4. Generate Measurement
        if [ ! -d "sev-snp-measure" ]; then
            git clone https://github.com/virtee/sev-snp-measure.git
        fi
        if [ ! -d "usr/share/edk2/ovmf" ]; then
            wget -q https://download.rockylinux.org/pub/rocky/10.1/devel/x86_64/os/Packages/e/edk2-ovmf-20250523-2.el10.noarch.rpm
            rpm2cpio edk2-ovmf-20250523-2.el10.noarch.rpm | cpio -idmv
        fi

        pip3 install -r ./sev-snp-measure/requirements.txt --break-system-packages 2>/dev/null || pip3 install -r ./sev-snp-measure/requirements.txt

        python3 ./sev-snp-measure/sev-snp-measure.py \
            --mode snp \
            --vcpus=2 \
            --vcpu-type=EPYC-v3 \
            --ovmf=./usr/share/edk2/ovmf/OVMF.amdsev.fd \
            --kernel=./linux-kernel/arch/x86/boot/bzImage \
            --initrd=./zero_trust_os.cpio \
            --append="console=ttyS0 ip=dhcp quiet loglevel=0 random.trust_cpu=on random.trust_bootloader=off amd_iommu=force_isolation iommu.strict=1 iommu.passthrough=0 mitigations=auto,nosmt spectre_v2=on pti=on gather_data_sampling=force srso=safe-ret retbleed=auto,nosmt lockdown=confidentiality" | tr -d "\n" > sev_measurement.txt

        echo "=== FINAL SEV-SNP MEASUREMENT ==="
        cat sev_measurement.txt
        echo
    '
