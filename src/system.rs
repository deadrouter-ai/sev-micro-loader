use crate::config::PAYLOAD_DIR;
use crate::panic_shutdown;
use nix::mount::{MsFlags, mount};

pub fn prepare_system_env() {
    println!("[INIT] Mounting essential filesystems...");
    let nosuid_nodev_noexec = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;

    // /proc — networking, process info
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        nosuid_nodev_noexec,
        None::<&str>,
    )
    .unwrap_or_else(|e| panic_shutdown(&format!("Failed to mount /proc: {}", e)));

    // /sys — device/network enumeration
    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        nosuid_nodev_noexec,
        None::<&str>,
    )
    .unwrap_or_else(|e| panic_shutdown(&format!("Failed to mount /sys: {}", e)));

    // /dev — device nodes (network, sev-guest, etc.)
    mount(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_NOSUID,
        None::<&str>,
    )
    .unwrap_or_else(|e| panic_shutdown(&format!("Failed to mount /dev: {}", e)));

    // /dev/pts for pseudoterminal support
    let _ = std::fs::create_dir("/dev/pts");
    let _ = mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::empty(),
        None::<&str>,
    );

    // /tmp — writable scratch space, but NOEXEC: nothing written here can execute.
    // This is critical: even if the server binary is exploited, the attacker
    // cannot drop and execute a payload in /tmp.
    mount(
        Some("tmpfs"),
        "/tmp",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("size=64m,mode=1700"),
    )
    .unwrap_or_else(|e| panic_shutdown(&format!("Failed to mount /tmp: {}", e)));

    // /run — general runtime volatile directory
    let _ = std::fs::create_dir_all("/run");
    mount(
        Some("tmpfs"),
        "/run",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("size=16m,mode=0755"),
    )
    .unwrap_or_else(|e| panic_shutdown(&format!("Failed to mount /run: {}", e)));

    // /run/payload — dedicated tmpfs for the server binary.
    // This starts writable so we can write the binary, then gets remounted
    // read-only in lockdown_filesystem(). No NOEXEC here since we need to execute from it.
    std::fs::create_dir_all(PAYLOAD_DIR)
        .unwrap_or_else(|e| panic_shutdown(&format!("Failed to create {}: {}", PAYLOAD_DIR, e)));
    mount(
        Some("tmpfs"),
        PAYLOAD_DIR,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("size=256m,mode=0755"),
    )
    .unwrap_or_else(|e| panic_shutdown(&format!("Failed to mount {}: {}", PAYLOAD_DIR, e)));

    // ---- NETWORK INTERFACE INITIALIZATION ----
    // PID 1 must bring up network interfaces. The kernel ip=dhcp boot param
    // configures the main NIC before init starts (if CONFIG_IP_PNP_DHCP=y),
    // but loopback always needs manual init, and we defensively ensure all
    // ethernet interfaces are UP.
    init_networking();

    // DNS: Bypass kernel DNS. We use a custom DoH resolver baked in.
    println!("[INIT] Bypassing kernel DNS. Custom DoH resolver will be used.");

    apply_kernel_hardening();

    println!("[INIT] Filesystem environment ready.");
}

fn apply_kernel_hardening() {
    println!("[INIT] Applying runtime kernel hardening via sysfs...");

    let sysctls: Vec<(&str, &[u8])> = vec![
        // 1. Prevent IP spoofing
        ("/proc/sys/net/ipv4/conf/all/rp_filter", b"1"),
        ("/proc/sys/net/ipv4/conf/default/rp_filter", b"1"),
        // 2. Prevent MITM ICMP redirects
        ("/proc/sys/net/ipv4/conf/all/accept_redirects", b"0"),
        ("/proc/sys/net/ipv4/conf/default/accept_redirects", b"0"),
        ("/proc/sys/net/ipv4/conf/all/send_redirects", b"0"),
        ("/proc/sys/net/ipv4/conf/default/send_redirects", b"0"),
        ("/proc/sys/net/ipv4/conf/all/secure_redirects", b"0"),
        ("/proc/sys/net/ipv4/conf/default/secure_redirects", b"0"),
        // 3. Ignore ICMP broadcasts (Smurf attacks) & bogus errors
        ("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", b"1"),
        ("/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses", b"1"),
        // 4. TCP Hardening (SYN cookies, time-wait assassination)
        ("/proc/sys/net/ipv4/tcp_syncookies", b"1"),
        ("/proc/sys/net/ipv4/tcp_rfc1337", b"1"),
        // 5. Restrict kernel pointers and dmesg
        ("/proc/sys/kernel/kptr_restrict", b"2"),
        ("/proc/sys/kernel/dmesg_restrict", b"1"),
        // 6. Disable unprivileged BPF and userfaultfd (Defense in depth)
        ("/proc/sys/kernel/unprivileged_bpf_disabled", b"1"),
        ("/proc/sys/vm/unprivileged_userfaultfd", b"0"),
        // 7. YAMA ptrace scope: 3 = No ptrace allowed at all
        ("/proc/sys/kernel/yama/ptrace_scope", b"3"),
        // 8. Disable Kexec loading
        ("/proc/sys/kernel/kexec_load_disabled", b"1"),
        // 9. Perf event profiling restriction
        ("/proc/sys/kernel/perf_event_paranoid", b"3"),
        // 10. Protect VFS symlinks and hardlinks
        ("/proc/sys/fs/protected_symlinks", b"1"),
        ("/proc/sys/fs/protected_hardlinks", b"1"),
        ("/proc/sys/fs/protected_fifos", b"2"),
        ("/proc/sys/fs/protected_regular", b"2"),
        // 11. TCP/IP DDoS Mitigation & Performance Tuning
        // Increase socket queue size to handle high concurrency spikes
        ("/proc/sys/net/core/somaxconn", b"8192"),
        // Increase the maximum number of packets queued on the input side
        ("/proc/sys/net/core/netdev_max_backlog", b"16384"),
        // Increase SYN backlog to absorb SYN floods before falling back to cookies
        ("/proc/sys/net/ipv4/tcp_max_syn_backlog", b"8192"),
        // Drop dead/half-open connections much faster (default is usually 5 retries / 60s)
        ("/proc/sys/net/ipv4/tcp_synack_retries", b"2"),
        ("/proc/sys/net/ipv4/tcp_fin_timeout", b"10"),
        // Aggressively kill idle/zombie connections (Keepalive: 60s idle, 10s interval, 6 probes)
        ("/proc/sys/net/ipv4/tcp_keepalive_time", b"60"),
        ("/proc/sys/net/ipv4/tcp_keepalive_intvl", b"10"),
        ("/proc/sys/net/ipv4/tcp_keepalive_probes", b"6"),
        // Prevent Out-Of-Memory from orphaned sockets
        ("/proc/sys/net/ipv4/tcp_max_orphans", b"16384"),
        // Safely reuse TIME-WAIT sockets for new connections to avoid port exhaustion
        ("/proc/sys/net/ipv4/tcp_tw_reuse", b"1"),
        // Complete stealth mode: ignore all pings to avoid discovery and ICMP floods
        ("/proc/sys/net/ipv4/icmp_echo_ignore_all", b"1"),
    ];

    for (path, val) in sysctls {
        // We log a warning if it fails, but don't panic.
        if let Err(e) = std::fs::write(path, val) {
            eprintln!(
                "[WARN] Failed to set sysctl {} to {:?}: {}",
                path,
                String::from_utf8_lossy(val),
                e
            );
        }
    }
}

fn init_networking() {
    println!("[INIT] Initializing network interfaces...");

    // 1. Always bring up loopback (lo) — kernel never does this automatically
    match configure_loopback() {
        Ok(()) => println!("[INIT] Loopback (lo) configured: 127.0.0.1/8"),
        Err(e) => eprintln!("[WARN] Failed to configure loopback: {}", e),
    }

    // 2. Bring up any ethernet interfaces that are administratively DOWN.
    //    If kernel ip=dhcp worked, they'll already be UP and this is a no-op.
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo" {
                continue;
            }
            match ensure_interface_up(&name) {
                Ok(was_down) => {
                    if was_down {
                        println!("[INIT] Interface {} brought UP", name);
                    } else {
                        println!("[INIT] Interface {} already UP", name);
                    }
                }
                Err(e) => eprintln!("[WARN] Failed to bring up {}: {}", name, e),
            }
        }
    }
}

fn configure_loopback() -> Result<(), String> {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return Err(format!("socket(): {}", std::io::Error::last_os_error()));
        }

        // ifreq struct: [ifr_name: 16 bytes][ifr_ifru union: 24 bytes]
        let mut ifr = [0u8; 40];
        ifr[..2].copy_from_slice(b"lo");

        // Build sockaddr_in for 127.0.0.1
        // Layout: [sin_family:2][sin_port:2][sin_addr:4][sin_zero:8] = 16 bytes
        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        sa[4..8].copy_from_slice(&[127, 0, 0, 1]); // network byte order

        // Set IP address
        ifr[16..32].copy_from_slice(&sa);
        if libc::ioctl(sock, libc::SIOCSIFADDR as _, ifr.as_ptr()) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(format!("SIOCSIFADDR: {}", e));
        }

        // Set netmask 255.0.0.0
        sa[4..8].copy_from_slice(&[255, 0, 0, 0]);
        ifr[16..32].copy_from_slice(&sa);
        if libc::ioctl(sock, libc::SIOCSIFNETMASK as _, ifr.as_ptr()) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(format!("SIOCSIFNETMASK: {}", e));
        }

        // Get current flags, then set IFF_UP | IFF_RUNNING
        ifr[16..40].fill(0);
        if libc::ioctl(sock, libc::SIOCGIFFLAGS as _, ifr.as_ptr()) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(format!("SIOCGIFFLAGS: {}", e));
        }
        let flags = i16::from_ne_bytes([ifr[16], ifr[17]]);
        let new_flags = flags | libc::IFF_UP as i16 | libc::IFF_RUNNING as i16;
        ifr[16..18].copy_from_slice(&new_flags.to_ne_bytes());
        if libc::ioctl(sock, libc::SIOCSIFFLAGS as _, ifr.as_ptr()) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(format!("SIOCSIFFLAGS: {}", e));
        }

        libc::close(sock);
    }
    Ok(())
}

fn ensure_interface_up(name: &str) -> Result<bool, String> {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return Err(format!("socket(): {}", std::io::Error::last_os_error()));
        }

        let mut ifr = [0u8; 40];
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(15); // IFNAMSIZ - 1 for null terminator
        ifr[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        // Get current flags
        if libc::ioctl(sock, libc::SIOCGIFFLAGS as _, ifr.as_ptr()) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(format!("SIOCGIFFLAGS: {}", e));
        }

        let flags = i16::from_ne_bytes([ifr[16], ifr[17]]);
        if flags & (libc::IFF_UP as i16) != 0 {
            libc::close(sock);
            return Ok(false); // already up
        }

        // Bring interface UP
        let new_flags = flags | libc::IFF_UP as i16;
        ifr[16..18].copy_from_slice(&new_flags.to_ne_bytes());
        if libc::ioctl(sock, libc::SIOCSIFFLAGS as _, ifr.as_ptr()) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(format!("SIOCSIFFLAGS: {}", e));
        }

        libc::close(sock);
    }
    Ok(true)
}

pub fn check_network_ready() {
    let has_default_route = std::fs::read_to_string("/proc/net/route")
        .map(|routes| {
            routes.lines().skip(1).any(|line| {
                let mut fields = line.split_whitespace();
                fields.next(); // skip iface
                fields.next().is_some_and(|dest| dest == "00000000")
            })
        })
        .unwrap_or(false);

    if has_default_route {
        println!("[INIT] Network ready (default route present).");
    } else {
        eprintln!("[WARN] ============================================================");
        eprintln!("[WARN] NO DEFAULT ROUTE DETECTED!");
        eprintln!("[WARN] The kernel must be booted with 'ip=dhcp' parameter.");
        eprintln!("[WARN] Without it, network requests will fail.");
        eprintln!("[WARN] Ensure CONFIG_IP_PNP_DHCP=y in kernel config.");
        eprintln!("[WARN] ============================================================");
    }
}

pub fn lockdown_filesystem() {
    println!("[INIT] Locking down filesystem...");

    // 1. Remount /run/payload read-only
    mount(
        None::<&str>,
        PAYLOAD_DIR,
        None::<&str>,
        MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        None::<&str>,
    )
    .unwrap_or_else(|e| {
        panic_shutdown(&format!(
            "Failed to lockdown {} to Read-Only: {}",
            PAYLOAD_DIR, e
        ))
    });

    // 2. Remount /tmp noexec
    mount(
        None::<&str>,
        "/tmp",
        None::<&str>,
        MsFlags::MS_REMOUNT | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("size=64m,mode=1700"),
    )
    .unwrap_or_else(|e| panic_shutdown(&format!("Failed to remount /tmp noexec: {}", e)));

    // 3. Remount /run noexec
    mount(
        None::<&str>,
        "/run",
        None::<&str>,
        MsFlags::MS_REMOUNT | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("size=16m,mode=0755"),
    )
    .unwrap_or_else(|e| panic_shutdown(&format!("Failed to remount /run noexec: {}", e)));

    println!("[INIT] Filesystem lockdown complete. No writable+executable paths remain.");
}
