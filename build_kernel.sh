#!/bin/bash
set -e

KERNEL_VER="6.18.33"

echo "Downloading Linux kernel source v$KERNEL_VER..."
wget -qO linux.tar.xz "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VER}.tar.xz"
tar -xf linux.tar.xz
rm -rf linux-kernel
mv linux-${KERNEL_VER} linux-kernel
cd linux-kernel

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
scripts/config --disable CONFIG_COMPAT
scripts/config --disable CONFIG_IA32_EMULATION
scripts/config --disable CONFIG_X86_X32_ABI
scripts/config --disable CONFIG_MODIFY_LDT_SYSCALL
scripts/config --disable CONFIG_PROC_KCORE
scripts/config --disable CONFIG_BPF_SYSCALL
scripts/config --disable CONFIG_EFI_TEST
scripts/config --disable CONFIG_EFI_CUSTOM_SSDT_OVERLAYS
scripts/config --disable CONFIG_ACPI_CUSTOM_METHOD
scripts/config --disable CONFIG_KPROBES
scripts/config --disable CONFIG_FTRACE

# 5. KSPP Kernel Hardening
scripts/config --enable CONFIG_RANDOMIZE_BASE
scripts/config --enable CONFIG_INIT_ON_ALLOC_DEFAULT_ON
scripts/config --enable CONFIG_INIT_ON_FREE_DEFAULT_ON
scripts/config --enable CONFIG_STRICT_KERNEL_RWX
scripts/config --enable CONFIG_STRICT_MODULE_RWX
scripts/config --enable CONFIG_SLAB_FREELIST_RANDOM
scripts/config --enable CONFIG_SLAB_FREELIST_HARDENED
scripts/config --enable CONFIG_HARDENED_USERCOPY
scripts/config --disable CONFIG_HARDENED_USERCOPY_FALLBACK
scripts/config --enable CONFIG_FORTIFY_SOURCE
scripts/config --enable CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT
scripts/config --enable CONFIG_ZERO_CALL_USED_REGS
scripts/config --enable CONFIG_IOMMU_DEFAULT_DMA_STRICT
scripts/config --disable CONFIG_SLAB_MERGE_DEFAULT
scripts/config --enable CONFIG_SHUFFLE_PAGE_ALLOCATOR
scripts/config --enable CONFIG_BUG_ON_DATA_CORRUPTION
scripts/config --enable CONFIG_STRICT_DEVMEM
scripts/config --enable CONFIG_IO_STRICT_DEVMEM

# 6. Exploit Mitigation
scripts/config --enable CONFIG_PANIC_ON_OOPS
scripts/config --enable CONFIG_SECURITY_DMESG_RESTRICT
scripts/config --enable CONFIG_X86_SMAP
scripts/config --enable CONFIG_X86_SMEP
scripts/config --enable CONFIG_X86_UMIP
scripts/config --enable CONFIG_PAGE_TABLE_ISOLATION
scripts/config --enable CONFIG_RETPOLINE
scripts/config --enable CONFIG_LEGACY_VSYSCALL_NONE
scripts/config --enable CONFIG_STATIC_USERMODEHELPER

# 7. Lockdown Mode
scripts/config --enable CONFIG_SECURITY_LOCKDOWN_LSM
scripts/config --enable CONFIG_SECURITY_LOCKDOWN_LSM_EARLY
scripts/config --enable CONFIG_SECURITY_YAMA
scripts/config --set-str CONFIG_LSM "lockdown,yama"

# 8. Strip massive unnecessary subsystems & Legacy Network Protocols
scripts/config --disable CONFIG_SOUND
scripts/config --disable CONFIG_IO_URING
scripts/config --disable CONFIG_KSM
scripts/config --disable CONFIG_VT
scripts/config --disable CONFIG_NUMA
scripts/config --disable CONFIG_SCTP
scripts/config --disable CONFIG_DCCP
scripts/config --disable CONFIG_RDS
scripts/config --disable CONFIG_TIPC
scripts/config --disable CONFIG_ATM
scripts/config --disable CONFIG_L2TP
scripts/config --disable CONFIG_BRIDGE
scripts/config --disable CONFIG_VLAN_8021Q
scripts/config --disable CONFIG_DECNET
scripts/config --disable CONFIG_IPX
scripts/config --disable CONFIG_APPLETALK
scripts/config --disable CONFIG_X25
scripts/config --disable CONFIG_NET_SCHED
scripts/config --disable CONFIG_NETFILTER
scripts/config --disable CONFIG_BPF_JIT
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

# 9. Advanced Memory & Structure Hardening (Kicksecure/KSPP Defaults)
scripts/config --enable CONFIG_INIT_STACK_ALL_ZERO
scripts/config --enable CONFIG_GCC_PLUGIN_RANDSTRUCT
scripts/config --enable CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL
scripts/config --enable CONFIG_PAGE_POISONING
scripts/config --enable CONFIG_VMAP_STACK
scripts/config --enable CONFIG_SECRETMEM

# 10. Syscall & Application Security
scripts/config --enable CONFIG_SECCOMP
scripts/config --enable CONFIG_SECCOMP_FILTER
scripts/config --disable CONFIG_SYSFS_SYSCALL
scripts/config --disable CONFIG_USELIB

# 11. Defense in Depth for Kernel Symbols
scripts/config --enable CONFIG_TRIM_UNUSED_KSYMS

# 12. Nuke Debugging Info
scripts/config --disable CONFIG_DEBUG_INFO
scripts/config --enable CONFIG_DEBUG_INFO_NONE
scripts/config --disable CONFIG_DEBUG_KERNEL
scripts/config --disable CONFIG_KALLSYMS_ALL

# 13. Kicksecure / KSPP Additon
scripts/config --disable CONFIG_USERFAULTFD
scripts/config --disable CONFIG_X86_MSR
scripts/config --disable CONFIG_LDISC_AUTOLOAD
scripts/config --disable CONFIG_LIVEPATCH
scripts/config --disable CONFIG_ACPI_TABLE_UPGRADE
scripts/config --disable CONFIG_DEVPORT
scripts/config --enable CONFIG_SLUB_DEBUG
scripts/config --enable CONFIG_SLUB_DEBUG_ON

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
echo "Done! Kernel is at: linux-kernel/arch/x86/boot/bzImage"
