#!/bin/bash
set -e

# Use the latest 6.12 LTS kernel for maximum security patching and stability
KERNEL_VER="6.12.91"

echo "Downloading Linux kernel source v$KERNEL_VER..."
wget -qO linux.tar.xz "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VER}.tar.xz"
tar -xf linux.tar.xz
cd linux-${KERNEL_VER}

echo "Configuring minimal KVM guest kernel..."
make defconfig
make kvm_guest.config

echo "Applying Zero-Trust Hardening & Features..."

# 1. Networking & DHCP
scripts/config --enable CONFIG_VIRTIO_NET
scripts/config --enable CONFIG_IP_PNP
scripts/config --enable CONFIG_IP_PNP_DHCP

# 2. AMD SEV-SNP Encryption & Shared Memory
scripts/config --enable CONFIG_AMD_MEM_ENCRYPT
scripts/config --enable CONFIG_AMD_MEM_ENCRYPT_ACTIVE_BY_DEFAULT
scripts/config --enable CONFIG_KVM_AMD_SEV
scripts/config --enable CONFIG_SWIOTLB
scripts/config --enable CONFIG_SWIOTLB_DYNAMIC

# 3. SEV-SNP Guest Attestation
scripts/config --enable CONFIG_CRYPTO_DEV_CCP_GUEST
scripts/config --enable CONFIG_SEV_GUEST
scripts/config --enable CONFIG_TSM_REPORTS

# 4. Disable Unnecessary Modules & Interfaces
scripts/config --disable CONFIG_MODULES
scripts/config --disable CONFIG_USB_SUPPORT
scripts/config --disable CONFIG_BINFMT_MISC
scripts/config --disable CONFIG_MAGIC_SYSRQ
scripts/config --disable CONFIG_DEVMEM
scripts/config --disable CONFIG_DEBUG_FS

# 5. KSPP Kernel Hardening
scripts/config --enable CONFIG_RANDOMIZE_BASE
scripts/config --enable CONFIG_INIT_ON_ALLOC_DEFAULT_ON
scripts/config --enable CONFIG_INIT_ON_FREE_DEFAULT_ON
scripts/config --enable CONFIG_STRICT_KERNEL_RWX
scripts/config --enable CONFIG_STRICT_MODULE_RWX
scripts/config --enable CONFIG_SLAB_FREELIST_RANDOM
scripts/config --enable CONFIG_SLAB_FREELIST_HARDENED
scripts/config --enable CONFIG_HARDENED_USERCOPY
scripts/config --enable CONFIG_FORTIFY_SOURCE
scripts/config --enable CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT
scripts/config --enable CONFIG_ZERO_CALL_USED_REGS
scripts/config --enable CONFIG_IOMMU_DEFAULT_DMA_STRICT
scripts/config --disable CONFIG_SLAB_MERGE_DEFAULT

# 6. Exploit Mitigation
scripts/config --enable CONFIG_PANIC_ON_OOPS
scripts/config --enable CONFIG_SECURITY_DMESG_RESTRICT

# 7. Lockdown Mode
scripts/config --enable CONFIG_SECURITY_LOCKDOWN_LSM
scripts/config --enable CONFIG_SECURITY_LOCKDOWN_LSM_EARLY
scripts/config --set-str CONFIG_LSM "lockdown,yama,bpf"

# 8. Strip massive unnecessary subsystems
scripts/config --disable CONFIG_SOUND
scripts/config --disable CONFIG_WLAN
scripts/config --disable CONFIG_BT
scripts/config --disable CONFIG_DRM
scripts/config --disable CONFIG_FB
scripts/config --disable CONFIG_USB
scripts/config --disable CONFIG_USER_NS
scripts/config --disable CONFIG_COREDUMP
scripts/config --disable CONFIG_KEXEC
scripts/config --disable CONFIG_KEXEC_FILE
scripts/config --disable CONFIG_SUSPEND
scripts/config --disable CONFIG_HIBERNATION
scripts/config --disable CONFIG_NET_VENDOR_INTEL
scripts/config --disable CONFIG_NET_VENDOR_AMD
scripts/config --disable CONFIG_NET_VENDOR_BROADCOM
scripts/config --disable CONFIG_NET_VENDOR_REALTEK
scripts/config --disable CONFIG_WIRELESS
scripts/config --disable CONFIG_ATA
scripts/config --disable CONFIG_SCSI_LOWLEVEL
scripts/config --disable CONFIG_INPUT_MOUSE
scripts/config --disable CONFIG_INPUT_JOYSTICK
scripts/config --disable CONFIG_INPUT_TOUCHSCREEN
scripts/config --disable CONFIG_FAT_FS
scripts/config --disable CONFIG_NTFS_FS
scripts/config --disable CONFIG_NETWORK_FILESYSTEMS
scripts/config --disable CONFIG_MISC_FILESYSTEMS

# 9. Nuke Debugging Info
scripts/config --disable CONFIG_DEBUG_INFO
scripts/config --enable CONFIG_DEBUG_INFO_NONE
scripts/config --disable CONFIG_DEBUG_KERNEL
scripts/config --disable CONFIG_KALLSYMS_ALL

echo "Resolving dependencies and finalizing configuration..."
make olddefconfig

echo "Compiling the kernel (this will take a few minutes)..."
export KBUILD_BUILD_TIMESTAMP="1970-01-01 00:00:00"
export KBUILD_BUILD_USER="builder"
export KBUILD_BUILD_HOST="buildhost"
export KBUILD_BUILD_VERSION="1"
export SOURCE_DATE_EPOCH=0
make -j$(nproc) bzImage

echo ""
echo "Done! Kernel is at: linux-${KERNEL_VER}/arch/x86/boot/bzImage"
