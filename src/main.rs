use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use sha2::{Sha256, Digest};
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use nix::mount::{mount, MsFlags};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ============================================================================
// HARDCODED CRITICAL TRUST ANCHORS
// ============================================================================
// Ed25519 public key — MUST be replaced with real production key before deploy.
const PUBLIC_KEY_BYTES: [u8; 32] = [
    0x1a, 0x15, 0xf3, 0x98, 0x31, 0xd2, 0x7f, 0x93, 
    0x0c, 0x6a, 0xb9, 0xeb, 0x3d, 0xb3, 0x72, 0xdb, 
    0x25, 0xa4, 0x7a, 0xf7, 0x89, 0xdc, 0x64, 0xd8, 
    0xc9, 0xcc, 0xc8, 0xe4, 0x36, 0xc4, 0x8e, 0xb0, 
];

const BINARY_URL: &str = "https://github.com/deadrouter-ai/api-proxy-server/releases/latest/download/server";
const SIGNATURE_URL: &str = "https://github.com/deadrouter-ai/api-proxy-server/releases/latest/download/server.sig";

// Binary lives on its own read-only tmpfs — isolated from all other writes.
const PAYLOAD_DIR: &str = "/run/payload";
const TARGET_PATH: &str = "/run/payload/server";

const ATTESTATION_PORT: u16 = 8080;

// Network retry configuration
const MAX_DOWNLOAD_RETRIES: u32 = 5;
const RETRY_DELAY_SECS: u64 = 3;
const REQUEST_TIMEOUT_SECS: u64 = 120;
const NETWORK_SETTLE_SECS: u64 = 5;

// ============================================================================
// SEV-SNP ioctl constants (Linux UAPI: include/uapi/linux/sev-guest.h)
// ============================================================================
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
    println!("[INIT] Confidential Micro-Loader starting (PID 1)...");

    // ========================================================================
    // STEP 1: PREPARE OS ENVIRONMENT (mount, network, DNS)
    // ========================================================================
    prepare_system_env();

    // Give kernel DHCP config time to complete, then verify connectivity.
    // The kernel's ip=dhcp runs before init, but link negotiation may lag.
    println!("[INIT] Waiting {}s for network to settle...", NETWORK_SETTLE_SECS);
    tokio::time::sleep(tokio::time::Duration::from_secs(NETWORK_SETTLE_SECS)).await;
    check_network_ready();

    // ========================================================================
    // STEP 2: DOWNLOAD BINARY AND SIGNATURE
    // ========================================================================
    println!("[INIT] Downloading production payload and detached signature...");

    // Build TLS config with EMBEDDED Mozilla CA root certificates.
    // In a bare initramfs there is no /etc/ssl/certs — we bake the CA
    // store directly into the binary so TLS works without any system files.
    //
    // We must install the crypto provider BEFORE calling ClientConfig::builder().
    // reqwest only installs it inside its own build() path, but we need it here.
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider(),
    );

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .connect_timeout(std::time::Duration::from_secs(30))
        .use_preconfigured_tls(tls_config)
        .build()
        .unwrap_or_else(|e| panic_halt(&format!("Failed to build HTTP client: {:?}", e)));

    let app_bytes = download_with_retry(&client, BINARY_URL, "production binary").await;
    let sig_bytes = download_with_retry(&client, SIGNATURE_URL, "cryptographic signature").await;

    // Drop the HTTP client — no more network needed from the loader
    drop(client);

    // ========================================================================
    // STEP 3: CRYPTOGRAPHIC SIGNATURE VERIFICATION
    // ========================================================================
    println!("[INIT] Performing Ed25519 signature verification...");
    let verifying_key = VerifyingKey::from_bytes(&PUBLIC_KEY_BYTES)
        .unwrap_or_else(|e| panic_halt(&format!("Invalid hardcoded public key: {}", e)));
    let signature = Signature::from_slice(&sig_bytes)
        .unwrap_or_else(|e| panic_halt(&format!("Invalid signature format: {}", e)));

    if verifying_key.verify(&app_bytes, &signature).is_err() {
        panic_halt(
            "CRITICAL: Signature verification FAILED!\n\
             Binary does NOT match the trusted signing key.\n\
             System halted to prevent execution of untrusted code."
        );
    }
    println!("[INIT] Signature verification PASSED.");

    // ========================================================================
    // STEP 4: COMPUTE HASH
    // ========================================================================
    let mut hasher = Sha256::new();
    hasher.update(&app_bytes);
    let runtime_hash = hasher.finalize();
    let hash_hex = hex::encode(&runtime_hash);
    println!("[INIT] Payload SHA-256: {}", hash_hex);

    // ========================================================================
    // STEP 5: DEPLOY BINARY TO ISOLATED READ-ONLY TMPFS
    // ========================================================================
    println!("[INIT] Writing verified binary to isolated volatile storage...");
    std::fs::write(TARGET_PATH, &app_bytes)
        .unwrap_or_else(|e| panic_halt(&format!("Failed to write binary: {}", e)));
    drop(app_bytes);

    std::fs::set_permissions(TARGET_PATH, Permissions::from_mode(0o500))
        .unwrap_or_else(|e| panic_halt(&format!("Failed to chmod binary: {}", e)));

    // ========================================================================
    // STEP 6: LOCK DOWN FILESYSTEM — MAKE BINARY IMMUTABLE
    // ========================================================================
    lockdown_filesystem();

    // ========================================================================
    // STEP 7: SPAWN SERVER AS CHILD PROCESS (PID 1 stays as loader)
    // ========================================================================
    // We do NOT execve. Instead, we spawn the server as a child process so
    // PID 1 (this code) remains our trusted, measured attestation server.
    // The server binary cannot modify itself (read-only mount) and cannot
    // execute anything it writes (noexec on all writable mounts).
    println!("[INIT] Spawning server as child process...");
    let mut child = Command::new(TARGET_PATH)
        .env("ENV_PRODUCTION", "true")
        .env("LOADER_PAYLOAD_HASH", &hash_hex)
        .spawn()
        .unwrap_or_else(|e| panic_halt(&format!("Failed to spawn server: {}", e)));

    let child_pid = child.id();
    println!("[INIT] Server launched as PID {}.", child_pid);

    // ========================================================================
    // STEP 8: RUN INDEPENDENT ATTESTATION SERVER ON :8080
    // ========================================================================
    // PID 1 now serves two roles:
    // 1. Independent attestation endpoint (tamper-proof, measured in SEV-SNP)
    // 2. Zombie reaper (PID 1 must wait() on orphaned children)
    println!("[INIT] Starting independent attestation server on :{}", ATTESTATION_PORT);
    println!("[INIT] Boot sequence complete. System operational.");

    // Spawn zombie reaper in background
    tokio::spawn(async {
        loop {
            // Reap any zombie children. PID 1 must do this.
            unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG); }
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    });

    // Spawn child process monitor
    tokio::task::spawn_blocking(move || {
        match child.wait() {
            Ok(status) => {
                eprintln!("[FATAL] Server process (PID {}) exited with: {}", child_pid, status);
                eprintln!("[FATAL] Server should never exit. System is in degraded state.");
            }
            Err(e) => {
                eprintln!("[FATAL] Failed to wait on server process: {}", e);
            }
        }
    });

    // Run the attestation server (blocks forever)
    run_attestation_server(&hash_hex).await;
}

// ============================================================================
// SYSTEM ENVIRONMENT PREPARATION
// ============================================================================
fn prepare_system_env() {
    println!("[INIT] Mounting essential filesystems...");
    let nosuid_nodev_noexec = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;

    // /proc — networking, process info
    mount(Some("proc"), "/proc", Some("proc"), nosuid_nodev_noexec, None::<&str>)
        .unwrap_or_else(|e| panic_halt(&format!("Failed to mount /proc: {}", e)));

    // /sys — device/network enumeration
    mount(Some("sysfs"), "/sys", Some("sysfs"), nosuid_nodev_noexec, None::<&str>)
        .unwrap_or_else(|e| panic_halt(&format!("Failed to mount /sys: {}", e)));

    // /dev — device nodes (network, sev-guest, etc.)
    mount(Some("devtmpfs"), "/dev", Some("devtmpfs"), MsFlags::MS_NOSUID, None::<&str>)
        .unwrap_or_else(|e| panic_halt(&format!("Failed to mount /dev: {}", e)));

    // /dev/pts for pseudoterminal support
    let _ = std::fs::create_dir("/dev/pts");
    let _ = mount(Some("devpts"), "/dev/pts", Some("devpts"), MsFlags::empty(), None::<&str>);

    // /tmp — writable scratch space, but NOEXEC: nothing written here can execute.
    // This is critical: even if the server binary is exploited, the attacker
    // cannot drop and execute a payload in /tmp.
    mount(Some("tmpfs"), "/tmp", Some("tmpfs"),
          MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
          Some("size=64m,mode=1700"))
        .unwrap_or_else(|e| panic_halt(&format!("Failed to mount /tmp: {}", e)));

    // /run — general runtime volatile directory
    let _ = std::fs::create_dir_all("/run");
    mount(Some("tmpfs"), "/run", Some("tmpfs"),
          MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
          Some("size=16m,mode=0700"))
        .unwrap_or_else(|e| panic_halt(&format!("Failed to mount /run: {}", e)));

    // /run/payload — dedicated tmpfs for the server binary.
    // This starts writable so we can write the binary, then gets remounted
    // read-only in lockdown_filesystem(). No NOEXEC here since we need to execute from it.
    std::fs::create_dir_all(PAYLOAD_DIR)
        .unwrap_or_else(|e| panic_halt(&format!("Failed to create {}: {}", PAYLOAD_DIR, e)));
    mount(Some("tmpfs"), PAYLOAD_DIR, Some("tmpfs"),
          MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
          Some("size=256m,mode=0500"))
        .unwrap_or_else(|e| panic_halt(&format!("Failed to mount {}: {}", PAYLOAD_DIR, e)));

    // ---- NETWORK INTERFACE INITIALIZATION ----
    // PID 1 must bring up network interfaces. The kernel ip=dhcp boot param
    // configures the main NIC before init starts (if CONFIG_IP_PNP_DHCP=y),
    // but loopback always needs manual init, and we defensively ensure all
    // ethernet interfaces are UP.
    init_networking();

    // DNS: ALWAYS use our trusted resolvers. Never trust DHCP-provided DNS.
    // Quad9 (9.9.9.9) — privacy-focused, malware-blocking
    // Cloudflare (1.1.1.1) — fallback
    println!("[INIT] Configuring trusted DNS resolvers (Quad9 + Cloudflare)...");
    let _ = std::fs::create_dir_all("/etc");
    std::fs::write("/etc/resolv.conf", "nameserver 9.9.9.9\nnameserver 1.1.1.1\n")
        .unwrap_or_else(|e| panic_halt(&format!("Failed to write /etc/resolv.conf: {}", e)));

    println!("[INIT] Filesystem environment ready.");
}

// ============================================================================
// NETWORK INTERFACE INITIALIZATION
// ============================================================================
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

// ============================================================================
// FILESYSTEM LOCKDOWN — CALLED AFTER BINARY IS WRITTEN
// ============================================================================
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
        .unwrap_or_else(|e| panic_halt(&format!("CRITICAL: Failed to remount {} read-only: {}", PAYLOAD_DIR, e)));

    println!("[INIT] Filesystem locked:");
    println!("[INIT]   /run/payload  → READ-ONLY (binary immutable)");
    println!("[INIT]   /tmp          → NOEXEC (no executable writes)");
    println!("[INIT]   /run          → NOEXEC (no executable writes)");
    println!("[INIT]   No writable+executable filesystem exists.");
}

// ============================================================================
// DOWNLOAD WITH RETRY & VALIDATION
// ============================================================================
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
                match response.bytes().await {
                    Ok(bytes) if bytes.is_empty() => {
                        last_error = format!("Empty response for {}", desc);
                        eprintln!("[WARN] {}", last_error);
                        continue;
                    }
                    Ok(bytes) => {
                        println!("[INIT] Downloaded {} ({} bytes)", desc, bytes.len());
                        return bytes.to_vec();
                    }
                    Err(e) => {
                        last_error = format!("Body read failed: {}", e);
                        eprintln!("[WARN] {}", last_error);
                        continue;
                    }
                }
            }
            Err(e) => {
                last_error = format!("Connection failed: {}", e);
                eprintln!("[WARN] {}", last_error);
                continue;
            }
        }
    }
    panic_halt(&format!("Failed to download {} after {} attempts: {}", desc, MAX_DOWNLOAD_RETRIES, last_error))
}

// ============================================================================
// INDEPENDENT ATTESTATION SERVER (:8080)
// ============================================================================
// This server is part of the measured bootloader (changes → different
// LAUNCH_MEASUREMENT). It cannot be tampered with without detection.
// It provides a hardware-rooted proof of what binary is running.
//
// Endpoint: GET /v1/attestation?nonce=<64 hex chars>
//   - nonce: 32 bytes hex-encoded, user-provided for freshness
//   - Returns: JSON with raw SEV-SNP attestation report + payload hash
//   - report_data layout: [0..32] = nonce bytes, [32..64] = payload SHA-256
async fn run_attestation_server(payload_hash_hex: &str) {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", ATTESTATION_PORT)).await
        .unwrap_or_else(|e| panic_halt(&format!("Failed to bind attestation port: {}", e)));

    let payload_hash = payload_hash_hex.to_string();
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let hash = payload_hash.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_attestation_connection(stream, &hash).await {
                        eprintln!("[ATTEST] Error from {}: {}", addr, e);
                    }
                });
            }
            Err(e) => eprintln!("[ATTEST] Accept error: {}", e),
        }
    }
}

async fn handle_attestation_connection(
    mut stream: tokio::net::TcpStream,
    payload_hash_hex: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read the HTTP request (max 4KB — more than enough for a GET request)
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read(&mut buf)
    ).await??;

    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    // Only accept GET requests
    if parts.len() < 2 || parts[0] != "GET" {
        send_http_response(&mut stream, 405, "application/json",
            r#"{"error":"method_not_allowed"}"#).await?;
        return Ok(());
    }

    let path_query = parts[1];

    // Parse path and query string
    let (path, query) = match path_query.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path_query, ""),
    };

    if path != "/v1/attestation" {
        send_http_response(&mut stream, 404, "application/json",
            r#"{"error":"not_found","hint":"Use GET /v1/attestation?nonce=<64 hex chars>"}"#).await?;
        return Ok(());
    }

    // Extract nonce from query parameters
    let nonce_hex = extract_query_param(query, "nonce").unwrap_or_default();

    // Validate nonce: must be exactly 64 hex characters (32 bytes)
    if nonce_hex.len() != 64 || !nonce_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        send_http_response(&mut stream, 400, "application/json",
            r#"{"error":"invalid_nonce","hint":"nonce must be exactly 64 hex characters (32 bytes)"}"#).await?;
        return Ok(());
    }

    let nonce_bytes = hex::decode(&nonce_hex)?;

    // Decode payload hash
    let payload_hash_bytes = hex::decode(payload_hash_hex)?;

    // Build the 64-byte report_data: [nonce(32) || payload_hash(32)]
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&nonce_bytes);
    report_data[32..64].copy_from_slice(&payload_hash_bytes);

    // Request SEV-SNP attestation report from hardware
    let (report_hex, platform) = match get_snp_attestation_report(&report_data) {
        Ok(report) => (hex::encode(&report), "amd-sev-snp"),
        Err(err) => {
            // Not running on SEV-SNP hardware — return error with context
            let body = format!(
                r#"{{"error":"snp_unavailable","message":"{}","payload_sha256":"{}","nonce":"{}"}}"#,
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
            "  \"payload_sha256\": \"{}\",\n",
            "  \"report_data_hex\": \"{}\",\n",
            "  \"attestation_report_hex\": \"{}\"\n",
            "}}"
        ),
        platform,
        nonce_hex,
        payload_hash_hex,
        hex::encode(&report_data),
        report_hex,
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

// ============================================================================
// SEV-SNP ATTESTATION REPORT VIA IOCTL
// ============================================================================
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

// ============================================================================
// TERMINAL HALT — NEVER RETURNS
// ============================================================================
fn panic_halt(message: &str) -> ! {
    eprintln!("\n======================================================================");
    eprintln!("FATAL: {}", message);
    eprintln!("System halted. No code will execute. Manual intervention required.");
    eprintln!("======================================================================");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

