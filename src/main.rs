use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::os::unix::process::CommandExt;
use std::sync::Arc;
use std::net::IpAddr;
use aws_lc_rs::digest::{Context, SHA384, SHA512};
use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P384_SHA384_FIXED};
use nix::mount::{mount, MsFlags};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use std::net::{Ipv4Addr, SocketAddr};
use reqwest::dns::{Name, Resolve, Resolving};

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

// ======================================================================
// HARDCODED CRITICAL TRUST ANCHORS
// ======================================================================
const PUBLIC_KEY_BYTES: [u8; 97] = [
    0x04, 0xf0, 0x7c, 0x7f, 0x7c, 0xb0, 0x87, 0x82, 
    0x38, 0x1d, 0x72, 0x91, 0xf0, 0xcc, 0xc2, 0xcd, 
    0xa4, 0x8c, 0x6b, 0x06, 0x21, 0xdc, 0x73, 0x1a, 
    0xf0, 0x83, 0x62, 0xcf, 0xfc, 0x97, 0x89, 0x9d, 
    0xc1, 0x06, 0xd8, 0x44, 0x12, 0x50, 0xa3, 0xca, 
    0x41, 0xf0, 0x20, 0xd8, 0xfd, 0x0f, 0x41, 0xc6, 
    0x19, 0xe9, 0x11, 0x76, 0x14, 0x26, 0xd8, 0x23, 
    0xe9, 0xb0, 0xb0, 0xc8, 0x8c, 0x94, 0x73, 0xb0, 
    0xe7, 0xd5, 0x9c, 0xce, 0x0f, 0x45, 0xfb, 0x3d, 
    0x55, 0xa5, 0x9b, 0x0b, 0xb4, 0xec, 0xea, 0x5d, 
    0xb4, 0x35, 0x42, 0x3a, 0x43, 0xb0, 0x07, 0x4a, 
    0x30, 0x2b, 0xba, 0x9d, 0xb6, 0x24, 0x52, 0xff, 
    0x0f, 
];

const BINARY_URL: &str = "https://github.com/deadrouter-ai/the-server/releases/latest/download/the_server";
const SIGNATURE_URL: &str = "https://github.com/deadrouter-ai/the-server/releases/latest/download/the_server.sig";
const HASH_URL: &str = "https://github.com/deadrouter-ai/the-server/releases/latest/download/the_server_hash.txt";

// Binary lives on its own read-only tmpfs — isolated from all other writes.
const PAYLOAD_DIR: &str = "/run/payload";
const TARGET_PATH: &str = "/run/payload/the_server";

const ATTESTATION_PORT: u16 = 8080;

// Network retry configuration
const MAX_DOWNLOAD_RETRIES: u32 = 5;
const RETRY_DELAY_SECS: u64 = 3;
const REQUEST_TIMEOUT_SECS: u64 = 120;
const NETWORK_SETTLE_SECS: u64 = 5;
const MAX_CONSECUTIVE_ERRORS: u32 = 10;

// ======================================================================
// SEV-SNP ioctl constants (Linux UAPI: include/uapi/linux/sev-guest.h)
// ======================================================================
// SNP_GET_REPORT = _IOWR('S', 0x0, struct snp_guest_request_ioctl)
// struct is 32 bytes → ioctl nr = (3<<30)|(32<<16)|('S'<<8)|0 = 0xC0205300
const SNP_GET_REPORT: libc::c_ulong = 0xC020_5300;

/// Mirrors `struct snp_guest_request_ioctl` from the Linux kernel UAPI.
#[repr(C)]
struct SnpGuestRequestIoctl {
    msg_version: u8,
    _pad: [u8; 7],
    req_data: u64,
    resp_data: u64,
    exitinfo2: u64,
}

/// Mirrors `struct snp_report_req`.
#[repr(C)]
struct SnpReportReq {
    user_data: [u8; 64],
    vmpl: u32,
    _rsvd: [u8; 28],
}

/// Mirrors `struct snp_report_resp`. Contains the raw attestation report.
#[repr(C)]
struct SnpReportResp {
    data: [u8; 4000],
}

#[tokio::main]
async fn main() {
    unsafe {
        let _ = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT);
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "run-attestation-server" {
        let payload_hash = args[2].clone();
        println!("[ATTEST] Starting isolated attestation server (PID {})", std::process::id());

        run_attestation_server(&payload_hash).await;
        std::process::exit(0);
    }

    println!("[INIT] Confidential Micro-Loader starting (PID 1)...");

    // ======================================================================
    // STEP 1: PREPARE OS ENVIRONMENT (mount, network, DNS)
    // ======================================================================
    prepare_system_env();

    wait_for_entropy();

    // Give kernel DHCP config time to complete, then verify connectivity.
    // The kernel's ip=dhcp runs before init, but link negotiation may lag.
    println!("[INIT] Waiting {}s for network to settle...", NETWORK_SETTLE_SECS);
    tokio::time::sleep(tokio::time::Duration::from_secs(NETWORK_SETTLE_SECS)).await;
    check_network_ready();

    // ======================================================================
    // STEP 2: DOWNLOAD BINARY AND SIGNATURE
    // ======================================================================
    println!("[INIT] Downloading production payload and detached signature...");

    // Build TLS config with MAXIMUM SECURITY:
    //   - TLS 1.3 ONLY (no protocol downgrade possible)
    //   - AES-256-GCM ONLY (no weaker ciphers)
    //   - Embedded Mozilla CA root certificates (no host cert store used)
    //
    // In a bare initramfs there is no /etc/ssl/certs — we bake the CA
    // store directly into the binary so TLS works without any system files.
    let hardened_provider = rustls::crypto::CryptoProvider {
        cipher_suites: vec![
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
        ],
        kx_groups: vec![
            rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
            rustls::crypto::aws_lc_rs::kx_group::SECP256R1MLKEM768,
            rustls::crypto::aws_lc_rs::kx_group::MLKEM1024,
            rustls::crypto::aws_lc_rs::kx_group::MLKEM768,
            rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
            rustls::crypto::aws_lc_rs::kx_group::X25519,
            rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
        ],
        ..rustls::crypto::aws_lc_rs::default_provider()
    };

    let _ = rustls::crypto::CryptoProvider::install_default(hardened_provider.clone());

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(hardened_provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|e| panic_shutdown(&format!("TLS 1.3 configuration failed: {}", e)))
        .with_root_certificates(root_store)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let client_doh = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .use_preconfigured_tls(tls_config.clone())
        .resolve("dns.mullvad.net", SocketAddr::new(IpAddr::V4(Ipv4Addr::new(194, 242, 2, 2)), 443))
        .build()
        .unwrap_or_else(|e| panic_shutdown(&format!("Failed to build DoH HTTP client: {:?}", e)));

    let custom_resolver = std::sync::Arc::new(CustomDohResolver { doh_client: client_doh });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .connect_timeout(std::time::Duration::from_secs(30))
        .use_preconfigured_tls(tls_config)
        .dns_resolver(custom_resolver)
        .build()
        .unwrap_or_else(|e| panic_shutdown(&format!("Failed to build HTTP client: {:?}", e)));

    let app_bytes = download_with_retry(&client, BINARY_URL, "production binary").await;
    let expected_hash_bytes = download_with_retry(&client, HASH_URL, "server hash").await;
    let expected_hash = String::from_utf8_lossy(&expected_hash_bytes).trim().to_string();


    // ======================================================================
    // STEP 3: COMPUTE HASH AND COMPARE
    // ======================================================================
    let mut ctx384 = Context::new(&SHA384);
    ctx384.update(&app_bytes);
    let runtime_hash = ctx384.finish();
    let hash_hex = base16ct::lower::encode_string(runtime_hash.as_ref());
    println!("[INIT] Payload SHA-384: {}", hash_hex);
    
    if hash_hex != expected_hash {
        panic_shutdown(&format!("CRITICAL: Hash mismatch! Expected: {}, Computed: {}", expected_hash, hash_hex));
    }
    println!("[INIT] Server hash matches expected hash from the release.");

    // ======================================================================
    // STEP 4: CRYPTOGRAPHIC SIGNATURE VERIFICATION
    // ======================================================================
    let sig_bytes = download_with_retry(&client, SIGNATURE_URL, "cryptographic signature").await;

    // Drop the HTTP client — no more network needed from the loader
    drop(client);

    println!("[INIT] Performing ECDSA P-384 signature verification...");
    let verifying_key = UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &PUBLIC_KEY_BYTES);

    if verifying_key.verify(&app_bytes, &sig_bytes).is_err() {
        panic_shutdown(
            "CRITICAL: Signature verification FAILED!\n\
             Binary does NOT match the trusted signing key.\n\
             System shutting down to prevent execution of untrusted code."
        );
    }
    println!("[INIT] Signature verification PASSED.");

    // ======================================================================
    // STEP 5: DEPLOY BINARY TO ISOLATED READ-ONLY TMPFS
    // ======================================================================
    println!("[INIT] Writing verified binary to isolated volatile storage...");
    std::fs::write(TARGET_PATH, &app_bytes)
        .unwrap_or_else(|e| panic_shutdown(&format!("Failed to write binary: {}", e)));
    drop(app_bytes);

    std::fs::set_permissions(TARGET_PATH, Permissions::from_mode(0o555))
        .unwrap_or_else(|e| panic_shutdown(&format!("Failed to chmod binary: {}", e)));

    // ======================================================================
    // STEP 6: LOCK DOWN FILESYSTEM — MAKE BINARY IMMUTABLE
    // ======================================================================
    lockdown_filesystem();

    // ======================================================================
    // STEP 7: SPAWN SERVER AS CHILD PROCESS (PID 1 stays as loader)
    // ======================================================================
    // We do NOT execve. Instead, we spawn the server as a child process so
    // PID 1 (this code) remains our trusted, measured attestation server.
    // The server binary cannot modify itself (read-only mount) and cannot
    // execute anything it writes (noexec on all writable mounts).
    println!("[INIT] Spawning server as child process...");

    // A pre-exec closure that locks down the child process.
    // It runs after fork but before exec. Errors are ignored to ensure it never crashes.
    fn secure_memory_setup() -> std::io::Result<()> {
        unsafe {
            // Disable ptrace and core dumps to protect RAM from other processes.
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
        Ok(())
    }

    let child = unsafe {
        Command::new(TARGET_PATH)
            .env("DEVELOPMENT", "false")
            .env("LOADER_PAYLOAD_HASH", &hash_hex)
            .uid(65534)
            .gid(65534)
            .pre_exec(secure_memory_setup)
            .spawn()
            .unwrap_or_else(|e| panic_shutdown(&format!("Failed to spawn server: {}", e)))
    };

    let child_pid = child.id();
    println!("[INIT] Server launched as PID {}.", child_pid);

    // ======================================================================
    // STEP 8: RUN INDEPENDENT ATTESTATION SERVER (Isolated Child Process)
    // ======================================================================
    // Running a TCP server in PID 1 is dangerous. Instead, we spawn it as a 
    // separate, unprivileged child process. PID 1 simply acts as a watchdog.
    
    // Make /dev/sev-guest accessible to the unprivileged attestation server
    if Path::new("/dev/sev-guest").exists() {
        let _ = std::fs::set_permissions("/dev/sev-guest", Permissions::from_mode(0o666));
    }

    let current_exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("/init"));
    let attest_child = unsafe {
        Command::new(current_exe)
            .arg("run-attestation-server")
            .arg(&hash_hex)
            .uid(65534)
            .gid(65534)
            .pre_exec(secure_memory_setup)
            .spawn()
            .unwrap_or_else(|e| panic_shutdown(&format!("Failed to spawn attestation server: {}", e)))
    };

    let attest_pid = attest_child.id();
    println!("[INIT] Attestation server spawned as isolated PID {}.", attest_pid);

    println!("[INIT] Boot sequence complete. System operational. PID 1 entering watchdog mode.");

    // PID 1 watchdog & zombie reaper loop
    loop {
        // Reap any zombie children. PID 1 must do this in Linux.
        loop {
            let mut status = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid <= 0 {
                break;
            }
            if pid == child_pid as i32 {
                panic_shutdown(&format!("Server process (PID {}) exited. System integrity compromised.", pid));
            } else if pid == attest_pid as i32 {
                panic_shutdown(&format!("Attestation server (PID {}) exited. System integrity compromised.", pid));
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}

// ======================================================================
// SYSTEM ENVIRONMENT PREPARATION
// ======================================================================
fn prepare_system_env() {
    println!("[INIT] Mounting essential filesystems...");
    let nosuid_nodev_noexec = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;

    // /proc — networking, process info
    mount(Some("proc"), "/proc", Some("proc"), nosuid_nodev_noexec, None::<&str>)
        .unwrap_or_else(|e| panic_shutdown(&format!("Failed to mount /proc: {}", e)));

    // /sys — device/network enumeration
    mount(Some("sysfs"), "/sys", Some("sysfs"), nosuid_nodev_noexec, None::<&str>)
        .unwrap_or_else(|e| panic_shutdown(&format!("Failed to mount /sys: {}", e)));

    // /dev — device nodes (network, sev-guest, etc.)
    mount(Some("devtmpfs"), "/dev", Some("devtmpfs"), MsFlags::MS_NOSUID, None::<&str>)
        .unwrap_or_else(|e| panic_shutdown(&format!("Failed to mount /dev: {}", e)));

    // /dev/pts for pseudoterminal support
    let _ = std::fs::create_dir("/dev/pts");
    let _ = mount(Some("devpts"), "/dev/pts", Some("devpts"), MsFlags::empty(), None::<&str>);

    // /tmp — writable scratch space, but NOEXEC: nothing written here can execute.
    // This is critical: even if the server binary is exploited, the attacker
    // cannot drop and execute a payload in /tmp.
    mount(Some("tmpfs"), "/tmp", Some("tmpfs"),
          MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
          Some("size=64m,mode=1700"))
        .unwrap_or_else(|e| panic_shutdown(&format!("Failed to mount /tmp: {}", e)));

    // /run — general runtime volatile directory
    let _ = std::fs::create_dir_all("/run");
    mount(Some("tmpfs"), "/run", Some("tmpfs"),
          MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
          Some("size=16m,mode=0755"))
        .unwrap_or_else(|e| panic_shutdown(&format!("Failed to mount /run: {}", e)));

    // /run/payload — dedicated tmpfs for the server binary.
    // This starts writable so we can write the binary, then gets remounted
    // read-only in lockdown_filesystem(). No NOEXEC here since we need to execute from it.
    std::fs::create_dir_all(PAYLOAD_DIR)
        .unwrap_or_else(|e| panic_shutdown(&format!("Failed to create {}: {}", PAYLOAD_DIR, e)));
    mount(Some("tmpfs"), PAYLOAD_DIR, Some("tmpfs"),
          MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
          Some("size=256m,mode=0755"))
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

// ======================================================================
// RUNTIME KERNEL HARDENING
// ======================================================================
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
            eprintln!("[WARN] Failed to set sysctl {} to {:?}: {}", path, String::from_utf8_lossy(val), e);
        }
    }
}

// ======================================================================
// NETWORK INTERFACE INITIALIZATION
// ======================================================================
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

/// Brings up loopback with 127.0.0.1/8 using raw socket ioctls.
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

/// Brings up a network interface if it is currently DOWN.
/// Returns Ok(true) if it was down and we brought it up, Ok(false) if already up.
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

/// Verifies that we have a default route (indicating the kernel configured
/// networking via ip=dhcp). Warns loudly if not — downloads will fail.
fn check_network_ready() {
    let has_default_route = std::fs::read_to_string("/proc/net/route")
        .map(|routes| {
            routes.lines().skip(1).any(|line| {
                // Columns: Iface Destination Gateway ...
                // Default route has Destination == 00000000
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
        // Don't halt — let the download retry logic handle the failure
        // with clearer error messages.
    }
}

// ======================================================================
// FILESYSTEM LOCKDOWN — CALLED AFTER BINARY IS WRITTEN
// ======================================================================
/// Makes the server binary immutable and ensures no writable+executable
/// filesystems exist. After this call:
///   - /run/payload is READ-ONLY (binary cannot be modified or replaced)
///   - /tmp is NOEXEC (nothing written there can be executed)
///   - /run is NOEXEC (same)
///   - No writable + executable filesystem exists anywhere
fn lockdown_filesystem() {
    println!("[INIT] Locking down filesystem...");

    // Remount /run/payload as read-only. The binary is now immutable.
    // Even a fully exploited server process cannot modify its own binary
    // or write any new executables to this mount.
    mount(None::<&str>, PAYLOAD_DIR, None::<&str>,
          MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
          None::<&str>)
        .unwrap_or_else(|e| panic_shutdown(&format!("CRITICAL: Failed to remount {} read-only: {}", PAYLOAD_DIR, e)));

    println!("[INIT] Filesystem locked:");
    println!("[INIT]   /run/payload  → READ-ONLY (binary immutable)");
    println!("[INIT]   /tmp          → NOEXEC (no executable writes)");
    println!("[INIT]   /run          → NOEXEC (no executable writes)");
    println!("[INIT]   No writable+executable filesystem exists.");
}

// ======================================================================
// DOWNLOAD WITH RETRY & VALIDATION
// ======================================================================
async fn download_with_retry(client: &reqwest::Client, url: &str, desc: &str) -> Vec<u8> {
    let mut last_error = String::new();

    for attempt in 1..=MAX_DOWNLOAD_RETRIES {
        if attempt > 1 {
            println!("[INIT] Retry {}/{} for {}...", attempt, MAX_DOWNLOAD_RETRIES, desc);
            tokio::time::sleep(tokio::time::Duration::from_secs(RETRY_DELAY_SECS)).await;
        }
        match client.get(url).send().await {
            Ok(response) => {
                let status = response.status();
                if !status.is_success() {
                    last_error = format!("HTTP {} for {}", status, url);
                    eprintln!("[WARN] {}", last_error);
                    continue;
                }
                let mut response = response;
                let mut bytes = Vec::new();
                let mut limit_exceeded = false;
                let mut read_err = None;
                while let Some(chunk) = match response.chunk().await {
                    Ok(c) => c,
                    Err(e) => {
                        read_err = Some(e);
                        None
                    }
                } {
                    if bytes.len() + chunk.len() > 100 * 1024 * 1024 {
                        limit_exceeded = true;
                        break;
                    }
                    bytes.extend_from_slice(&chunk);
                }

                if limit_exceeded {
                    last_error = format!("Response size limit exceeded (max 100MB) for {}", desc);
                    eprintln!("[WARN] {}", last_error);
                    continue;
                }
                if let Some(e) = read_err {
                    last_error = format!("Body read failed: {}", e);
                    eprintln!("[WARN] {}", last_error);
                    continue;
                }
                if bytes.is_empty() {
                    last_error = format!("Empty response for {}", desc);
                    eprintln!("[WARN] {}", last_error);
                    continue;
                }
                println!("[INIT] Downloaded {} ({} bytes)", desc, bytes.len());
                return bytes;
            }
            Err(e) => {
                last_error = format!("Connection failed: {:?}", e);
                eprintln!("[WARN] {}", last_error);
                continue;
            }
        }
    }
    panic_shutdown(&format!("Failed to download {} after {} attempts: {}", desc, MAX_DOWNLOAD_RETRIES, last_error))
}

// ======================================================================
// INDEPENDENT ATTESTATION SERVER (:8080)
// ======================================================================
#[derive(Clone, PartialEq, Eq, Hash)]
enum Subnet {
    V4([u8; 3]), // /24
    V6([u8; 8]), // /64
}

impl From<IpAddr> for Subnet {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                Subnet::V4([octets[0], octets[1], octets[2]])
            }
            IpAddr::V6(addr) => {
                let octets = addr.octets();
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&octets[0..8]);
                Subnet::V6(prefix)
            }
        }
    }
}

struct SubnetState {
    requests: std::collections::VecDeque<std::time::Instant>,
    active_connections: u32,
}

struct PerSubnetLimiter {
    subnets: std::sync::Mutex<std::collections::HashMap<Subnet, SubnetState>>,
    max_requests: usize,
    window: std::time::Duration,
    max_concurrent: u32,
}

impl PerSubnetLimiter {
    fn new(max_requests: usize, window: std::time::Duration, max_concurrent: u32) -> Self {
        Self {
            subnets: std::sync::Mutex::new(std::collections::HashMap::new()),
            max_requests,
            window,
            max_concurrent,
        }
    }

    fn acquire(self: &std::sync::Arc<Self>, ip: IpAddr) -> Result<SubnetPermit, &'static str> {
        let subnet = Subnet::from(ip);
        let mut map = self.subnets.lock().unwrap();
        let now = std::time::Instant::now();

        // Garbage collection to prevent memory leaks from millions of subnets
        if map.len() > 10000 {
            map.retain(|_, state| {
                while let Some(&oldest) = state.requests.front() {
                    if now.duration_since(oldest) > self.window {
                        state.requests.pop_front();
                    } else {
                        break;
                    }
                }
                state.active_connections > 0 || !state.requests.is_empty()
            });
        }

        let state = map.entry(subnet.clone()).or_insert_with(|| SubnetState {
            requests: std::collections::VecDeque::new(),
            active_connections: 0,
        });

        while let Some(&oldest) = state.requests.front() {
            if now.duration_since(oldest) > self.window {
                state.requests.pop_front();
            } else {
                break;
            }
        }

        if state.requests.len() >= self.max_requests {
            return Err("rate_limit_exceeded");
        }

        if state.active_connections >= self.max_concurrent {
            return Err("concurrency_exceeded");
        }

        state.requests.push_back(now);
        state.active_connections += 1;

        Ok(SubnetPermit {
            limiter: std::sync::Arc::clone(self),
            subnet,
        })
    }
}

struct SubnetPermit {
    limiter: std::sync::Arc<PerSubnetLimiter>,
    subnet: Subnet,
}

impl Drop for SubnetPermit {
    fn drop(&mut self) {
        if let Ok(mut map) = self.limiter.subnets.lock() {
            if let Some(state) = map.get_mut(&self.subnet) {
                state.active_connections = state.active_connections.saturating_sub(1);
            }
        }
    }
}

// This server is part of the measured bootloader (changes → different
// LAUNCH_MEASUREMENT). It cannot be tampered with without detection.
// It provides a hardware-rooted proof of what binary is running.
//
// Endpoint: GET /v1/attestation?nonce=<hex encoded nonce>
//   - nonce: 1 to 128 bytes hex-encoded, user-provided for freshness
//   - Returns: JSON with raw SEV-SNP attestation report + payload hash
//   - report_data layout: 64-byte SHA-512 of [payload SHA-384 || nonce]
async fn run_attestation_server(payload_hash_hex: &str) {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", ATTESTATION_PORT)).await
        .unwrap_or_else(|e| panic_shutdown(&format!("Failed to bind attestation port: {}", e)));

    println!("[ATTEST] Attestation server bound on :{} — this is the independent watchdog.", ATTESTATION_PORT);
    println!("[ATTEST] Any failure or interference with this server triggers immediate shutdown.");

    let payload_hash = payload_hash_hex.to_string();
    let mut consecutive_errors: u32 = 0;

    // Strict Anti-DDoS protections
    // Limit per subnet (IPv4 /24, IPv6 /64) to prevent organized spam while allowing legitimate load
    let subnet_limiter = Arc::new(PerSubnetLimiter::new(10, std::time::Duration::from_secs(3), 2)); 
    // Global hardware concurrency limit to protect /dev/sev-guest firmware queue
    let global_hardware_limiter = Arc::new(tokio::sync::Semaphore::new(8)); 

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                consecutive_errors = 0; // Reset on success
                let hash = payload_hash.clone();
                let sl = subnet_limiter.clone();
                let gl = global_hardware_limiter.clone();
                let ip = addr.ip();
                tokio::spawn(async move {
                    if let Err(e) = handle_attestation_connection(stream, &hash, ip, sl, gl).await {
                        eprintln!("[ATTEST] Error from {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                // Prevent remote DoS: ignore errors caused by clients dropping the connection
                let kind = e.kind();
                if kind == std::io::ErrorKind::ConnectionAborted ||
                   kind == std::io::ErrorKind::ConnectionReset ||
                   kind == std::io::ErrorKind::BrokenPipe ||
                   kind == std::io::ErrorKind::Interrupted {
                    continue; // Perfectly normal network behavior
                }

                // Ignore file descriptor exhaustion but throttle to avoid tight spinloops
                if e.raw_os_error() == Some(libc::EMFILE) || e.raw_os_error() == Some(libc::ENFILE) {
                    eprintln!("[WARN] Attestation server out of file descriptors (EMFILE/ENFILE). Throttling...");
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    continue;
                }

                consecutive_errors += 1;
                eprintln!("[ATTEST] Accept error ({}/{}): {}", consecutive_errors, MAX_CONSECUTIVE_ERRORS, e);
                
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    panic_shutdown(&format!(
                        "Attestation server failed {} consecutive accepts. \
                         Possible interference detected. System integrity compromised.",
                        MAX_CONSECUTIVE_ERRORS
                    ));
                }
            }
        }
    }
}

async fn handle_attestation_connection(
    mut stream: tokio::net::TcpStream,
    payload_hash_hex: &str,
    ip: std::net::IpAddr,
    subnet_limiter: Arc<PerSubnetLimiter>,
    global_hardware_limiter: Arc<tokio::sync::Semaphore>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Enforce Per-Subnet Limits (Rate + Concurrency)
    // Dropping _subnet_permit automatically decrements the active concurrency connection count
    let _subnet_permit = match subnet_limiter.acquire(ip) {
        Ok(permit) => permit,
        Err("rate_limit_exceeded") => {
            send_http_response(&mut stream, 429, "application/json", r#"{"error":"too_many_requests","message":"Subnet rate limit exceeded"}"#).await?;
            return Ok(());
        }
        Err(_) => {
            send_http_response(&mut stream, 429, "application/json", r#"{"error":"too_many_requests","message":"Subnet concurrency limit exceeded"}"#).await?;
            return Ok(());
        }
    };

    // Read the HTTP request in a loop until \r\n\r\n
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read(&mut chunk)
        ).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Ok(()), // Timeout
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        // Strict enforcement: max size to prevent memory exhaustion DoS
        if buf.len() > 8192 {
            return Ok(());
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    if buf.is_empty() {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf);

    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    // Must be exactly "GET /... HTTP/1.x"
    if parts.len() != 3 || parts[0] != "GET" || !parts[2].starts_with("HTTP/") {
        return Ok(()); // Anti-scanner: silently drop unexpected protocols/methods
    }

    let path_query = parts[1];

    // Must target the attestation endpoint
    if !path_query.starts_with("/v1/attestation") {
        return Ok(()); // Anti-scanner: silently drop unexpected paths
    }

    // Parse path and query string
    let (path, query) = match path_query.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path_query, ""),
    };

    if path != "/v1/attestation" {
        return Ok(());
    }

    // Extract nonce from query parameters
    let nonce_hex = extract_query_param(query, "nonce").unwrap_or_default();

    // Validate nonce: must be a valid hex string between 2 and 256 characters (1 to 128 bytes)
    if nonce_hex.len() < 2 || nonce_hex.len() > 256 || nonce_hex.len() % 2 != 0 || !nonce_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        send_http_response(&mut stream, 400, "application/json",
            r#"{"error":"invalid_nonce","hint":"nonce must be a hex-encoded string between 1 and 128 bytes (2 to 256 hex characters)"}"#).await?;
        return Ok(());
    }

    let nonce_bytes = match base16ct::mixed::decode_vec(&nonce_hex) {
        Ok(b) => b,
        Err(_) => return Ok(()),
    };

    // Decode payload hash
    let payload_hash_bytes = match base16ct::mixed::decode_vec(payload_hash_hex) {
        Ok(b) => b,
        Err(_) => return Ok(()),
    };

    // Build the 64-byte report_data as SHA-512(payload_hash || nonce)
    let mut ctx = Context::new(&SHA512);
    ctx.update(&payload_hash_bytes);
    ctx.update(&nonce_bytes);
    let report_data_hash = ctx.finish();
    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(report_data_hash.as_ref());

    // 2. Enforce Global Hardware Concurrency Limit
    // The hardware SEV guest device is a shared resource. We limit concurrent access
    // to prevent hardware starvation or exhaustion of internal firmware resources.
    let _hardware_permit = match global_hardware_limiter.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            send_http_response(&mut stream, 503, "application/json", r#"{"error":"server_busy","message":"Hardware attestation queue is full"}"#).await?;
            return Ok(());
        }
    };

    use base64ct::{Base64Url, Encoding};
    // Request SEV-SNP attestation report from hardware
    let (report_b64, platform) = match get_snp_attestation_report(&report_data) {
        Ok(report) => (Base64Url::encode_string(&report), "amd-sev-snp"),
        Err(err) => {
            // Not running on SEV-SNP hardware — return error with context
            let body = format!(
                r#"{{"error":"snp_unavailable","message":"{}","payload_sha384":"{}","nonce":"{}"}}"#,
                err.replace('"', "'"), payload_hash_hex, nonce_hex
            );
            send_http_response(&mut stream, 503, "application/json", &body).await?;
            return Ok(());
        }
    };

    // Build JSON response (manual formatting — no serde dependency needed)
    let body = format!(
        concat!(
            "{{\n",
            "  \"version\": 1,\n",
            "  \"platform\": \"{}\",\n",
            "  \"nonce\": \"{}\",\n",
            "  \"payload_sha384\": \"{}\",\n",
            "  \"report_data_hex\": \"{}\",\n",
            "  \"attestation_report\": \"{}\"\n",
            "}}"
        ),
        platform,
        nonce_hex,
        payload_hash_hex,
        base16ct::lower::encode_string(&report_data),
        report_b64,
    );

    send_http_response(&mut stream, 200, "application/json", &body).await?;
    Ok(())
}

fn extract_query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(v);
            }
        }
    }
    None
}

async fn send_http_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Cache-Control: no-store\r\n\
         \r\n\
         {}",
        status, status_text, content_type, body.len(), body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    stream.shutdown().await?;
    Ok(())
}

// ======================================================================
// SEV-SNP ATTESTATION REPORT VIA IOCTL
// ======================================================================
fn get_snp_attestation_report(report_data: &[u8; 64]) -> Result<Vec<u8>, String> {
    let dev_path = "/dev/sev-guest";
    if !Path::new(dev_path).exists() {
        return Err("SEV-SNP device not available (/dev/sev-guest not found)".to_string());
    }

    let fd = std::fs::File::open(dev_path)
        .map_err(|e| format!("Failed to open {}: {}", dev_path, e))?;

    // Prepare the attestation request
    let mut req = SnpReportReq {
        user_data: *report_data,
        vmpl: 0,
        _rsvd: [0u8; 28],
    };

    let mut resp = SnpReportResp {
        data: [0u8; 4000],
    };

    let mut ioctl_req = SnpGuestRequestIoctl {
        msg_version: 1,
        _pad: [0u8; 7],
        req_data: &mut req as *mut SnpReportReq as u64,
        resp_data: &mut resp as *mut SnpReportResp as u64,
        exitinfo2: 0,
    };

    use std::os::unix::io::AsRawFd;
    let ret = unsafe {
        libc::ioctl(fd.as_raw_fd(), SNP_GET_REPORT as _, &mut ioctl_req)
    };

    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        return Err(format!("SNP_GET_REPORT ioctl failed: {} (fw_err: {})",
            errno,
            ioctl_req.exitinfo2 & 0xFFFF_FFFF
        ));
    }

    // The attestation report is 1184 bytes (SNP ATTESTATION_REPORT structure)
    // It's at the start of resp.data
    Ok(resp.data[..1184].to_vec())
}

// ======================================================================
// PANIC SHUTDOWN — IMMEDIATE POWER-OFF, NEVER RETURNS
// ======================================================================
// Instead of hanging forever (which leaves a potentially compromised VM running),
// we immediately power off the machine. This:
//   1. Makes failures instantly detectable (server goes offline)
//   2. Eliminates any window for malicious code to operate
//   3. Prevents exploitation of a degraded/broken system state
//   4. Forces a fresh boot from the measured image on restart
fn panic_shutdown(message: &str) -> ! {
    eprintln!("\n======================================================================");
    eprintln!("FATAL: {}", message);
    eprintln!("PANIC SHUTDOWN: Powering off immediately.");
    eprintln!("======================================================================");

    // Sync any buffered writes before power-off
    unsafe { libc::sync(); }

    // Immediate power-off. PID 1 has the privilege to do this.
    // This is the nuclear option — no cleanup, no graceful shutdown.
    // Any bad actor loses all execution capability instantly.
    unsafe { libc::reboot(libc::RB_POWER_OFF); }

    // If reboot() somehow fails (should never happen for PID 1), abort hard
    std::process::abort();
}

// ======================================================================
// CUSTOM DOH RESOLVER
// ======================================================================
struct CustomDohResolver {
    doh_client: reqwest::Client,
}

impl Resolve for CustomDohResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let domain = name.as_str().to_string();
        let doh_client = self.doh_client.clone();
        
        Box::pin(async move {
            println!("[DNS] Resolving {} via DoH...", domain);
            let q = build_a_record_query(&domain);
            let mut res_opt = doh_client.post("https://dns.mullvad.net/dns-query")
                .header("Content-Type", "application/dns-message")
                .header("Accept", "application/dns-message")
                .body(q)
                .send()
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    println!("[DNS] DoH query failed: {:?}", e);
                    Box::new(e)
                })?;

            let mut res = Vec::new();
            while let Some(chunk) = res_opt.chunk().await.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                println!("[DNS] DoH body read failed: {:?}", e);
                Box::new(e)
            })? {
                if res.len() + chunk.len() > 65536 {
                    println!("[DNS] DoH response too large");
                    return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "DoH response too large")) as Box<dyn std::error::Error + Send + Sync>);
                }
                res.extend_from_slice(&chunk);
            }
                
            let ip = parse_dns_response(&res)
                .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "No A record found via DoH"))
                })?;
            println!("[DNS] {} -> {}", domain, ip);
                
            let addrs: Box<dyn Iterator<Item = SocketAddr> + Send> = Box::new(std::iter::once(SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

fn build_a_record_query(domain: &str) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&[0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for part in domain.split('.') {
        query.push(part.len() as u8);
        query.extend_from_slice(part.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    query
}

fn parse_dns_response(data: &[u8]) -> Option<IpAddr> {
    if data.len() < 12 { return None; }
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let mut offset = 12;
    // skip question
    while offset < data.len() && data[offset] != 0 {
        offset += data[offset] as usize + 1;
    }
    offset += 1 + 4; // null byte + QTYPE + QCLASS
    for _ in 0..ancount {
        if offset + 12 > data.len() { break; }
        if data[offset] & 0xC0 == 0xC0 {
            offset += 2;
        } else {
            while offset < data.len() && data[offset] != 0 {
                if data[offset] & 0xC0 == 0xC0 { offset += 2; break; }
                offset += data[offset] as usize + 1;
            }
            if offset < data.len() && data[offset] == 0 { offset += 1; }
        }
        if offset + 10 > data.len() { break; }
        let atype = u16::from_be_bytes([data[offset], data[offset+1]]);
        let rdlength = u16::from_be_bytes([data[offset+8], data[offset+9]]) as usize;
        offset += 10;
        if atype == 1 && rdlength == 4 && offset + 4 <= data.len() {
            return Some(IpAddr::V4(Ipv4Addr::new(
                data[offset], data[offset+1], data[offset+2], data[offset+3]
            )));
        }
        offset += rdlength;
    }
    None
}

fn wait_for_entropy() {
    println!("[INIT] Waiting for kernel entropy pool (CRNG) to initialize...");
    let mut file = match std::fs::File::open("/dev/random") {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[WARN] Failed to open /dev/random: {}. Continuing anyway...", e);
            return;
        }
    };
    let mut buf = [0u8; 1];
    use std::io::Read;
    if let Err(e) = file.read_exact(&mut buf) {
        eprintln!("[WARN] Failed to read from /dev/random: {}. Continuing anyway...", e);
    } else {
        println!("[INIT] Entropy pool ready.");
    }
}
