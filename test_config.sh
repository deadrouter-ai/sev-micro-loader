#!/bin/bash
set -e
KERNEL_VER="6.12.91"
if [ ! -d "linux-${KERNEL_VER}" ]; then
  wget -qO linux.tar.xz "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VER}.tar.xz"
  tar -xf linux.tar.xz
fi
cd linux-${KERNEL_VER}
make defconfig
make kvm_guest.config

# 4. Disable Unnecessary Modules & Interfaces (Deep Attack Surface Reduction)
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

# 8. Additions
scripts/config --disable CONFIG_IO_URING
scripts/config --disable CONFIG_KSM
scripts/config --disable CONFIG_VT
scripts/config --disable CONFIG_NUMA

make olddefconfig
echo "Config test passed"
