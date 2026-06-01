mod attestation;
mod config;
mod crypto;
mod dns;
mod system;
mod time;

use aws_lc_rs::digest::{Context, SHA384};
use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED, UnparsedPublicKey};
use std::fs::Permissions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use crate::attestation::run_attestation_server;
use crate::config::{
    BINARY_URL, HASH_URL, NETWORK_SETTLE_SECS, PUBLIC_KEY_BYTES, REQUEST_TIMEOUT_SECS,
    SIGNATURE_URL, TARGET_PATH,
};
use crate::crypto::{download_with_retry, wait_for_entropy};
use crate::dns::{CustomDnscryptResolver, query_mullvad_secure_date, resolve_domain_via_dnscrypt};
use crate::system::{check_network_ready, lockdown_filesystem, prepare_system_env};
use crate::time::{
    LAST_KNOWN_GOOD_TIME_MICROS, ROUGHTIME_SERVERS, RoughtimeServer, enforce_time_floor,
    query_roughtime,
};

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

pub fn panic_shutdown(message: &str) -> ! {
    eprintln!("\n======================================================================");
    eprintln!("FATAL: {}", message);
    eprintln!("PANIC SHUTDOWN: Powering off immediately.");
    eprintln!("======================================================================\n");
    // Flush stdout/stderr
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    // Direct reboot syscall with command for power-off
    unsafe {
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }

    // Fallback if reboot syscall returns: exit with failure
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    unsafe {
        let _ = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT);
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "run-attestation-server" {
        let payload_hash = args[2].clone();
        println!(
            "[ATTEST] Starting isolated attestation server (PID {})",
            std::process::id()
        );

        run_attestation_server(&payload_hash).await;
        std::process::exit(0);
    }

    println!("[INIT] Confidential Micro-Loader starting (PID 1)...");

    // ======================================================================
    // STEP 1: PREPARE OS ENVIRONMENT (mount, network, DNS)
    // ======================================================================
    prepare_system_env();

    enforce_time_floor();

    wait_for_entropy();

    // Give kernel DHCP config time to complete, then verify connectivity.
    // The kernel's ip=dhcp runs before init, but link negotiation may lag.
    println!(
        "[INIT] Waiting {}s for network to settle...",
        NETWORK_SETTLE_SECS
    );
    tokio::time::sleep(tokio::time::Duration::from_secs(NETWORK_SETTLE_SECS)).await;
    check_network_ready();

    // ======================================================================
    // STEP 2: DOWNLOAD BINARY AND SIGNATURE
    // ======================================================================
    // Build TLS config with MAXIMUM SECURITY:
    let hardened_provider = rustls::crypto::CryptoProvider {
        cipher_suites: vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384],
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

    // ======================================================================
    // ROUGHTIME SECURE TIME SYNCHRONIZATION WITH TLS DATE FALLBACK
    // ======================================================================
    let mut resolved_servers = Vec::new();
    let mut dnscrypt_fallback_time = None;

    for srv in ROUGHTIME_SERVERS {
        let srv: &RoughtimeServer = srv;
        match resolve_domain_via_dnscrypt(srv.host).await {
            Ok((ip, fb_time)) => {
                println!("[DNS] Resolved {} to {}", srv.host, ip);
                resolved_servers.push((*srv, ip));
                if fb_time.is_some() && dnscrypt_fallback_time.is_none() {
                    dnscrypt_fallback_time = fb_time;
                }
            }
            Err(e) => {
                eprintln!(
                    "[WARN] Failed to resolve {} via DNSCrypt: {}. Using hardcoded fallback IP.",
                    srv.host, e
                );
                let fallback_ip = match srv.name {
                    "cloudflare" => std::net::IpAddr::V4(std::net::Ipv4Addr::new(162, 159, 200, 1)),
                    "roughtime.se" => {
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 36, 143, 134))
                    }
                    "roughtime.int08h.com" => {
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(51, 81, 57, 55))
                    }
                    "google" => std::net::IpAddr::V4(std::net::Ipv4Addr::new(173, 194, 45, 81)),
                    _ => continue,
                };
                resolved_servers.push((*srv, fallback_ip));
            }
        }
    }

    let midpoint = match query_roughtime(resolved_servers).await {
        Ok(m) => Some(m),
        Err(e) => {
            eprintln!(
                "[WARN] Failed to retrieve secure time from Roughtime: {}",
                e
            );
            if let Some(fb_time) = dnscrypt_fallback_time {
                println!(
                    "[TIME] Falling back to secure TLS Date header timestamp: {}s",
                    fb_time
                );
                Some(fb_time * 1_000_000)
            } else {
                println!(
                    "[TIME] Querying Mullvad secure connection check date..."
                );
                query_mullvad_secure_date(tls_config.clone())
                    .await
                    .map(|fb_time| fb_time * 1_000_000)
            }
        }
    };

    let midpoint = match midpoint {
        Some(m) => m,
        None => {
            panic_shutdown(
                "Failed to retrieve secure time from Roughtime AND TLS Date fallback. Unable to proceed securely.",
            );
        }
    };

    if midpoint < LAST_KNOWN_GOOD_TIME_MICROS {
        panic_shutdown(&format!(
            "Secure Roughtime/TLS time {} is before last known good time floor {}",
            midpoint, LAST_KNOWN_GOOD_TIME_MICROS
        ));
    }

    let secs = midpoint / 1_000_000;
    let nsecs = (midpoint % 1_000_000) * 1000;
    let ts = libc::timespec {
        tv_sec: secs as _,
        tv_nsec: nsecs as _,
    };
    unsafe {
        if libc::clock_settime(libc::CLOCK_REALTIME, &ts) != 0 {
            panic_shutdown("Failed to set system clock from Roughtime/TLS response");
        }
    }
    println!("[TIME] System clock updated: {}s", secs);

    let custom_resolver = std::sync::Arc::new(CustomDnscryptResolver::new());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .connect_timeout(std::time::Duration::from_secs(30))
        .use_preconfigured_tls(tls_config)
        .dns_resolver(custom_resolver)
        .build()
        .unwrap_or_else(|e| panic_shutdown(&format!("Failed to build HTTP client: {:?}", e)));

    let app_bytes = download_with_retry(&client, BINARY_URL, "production binary").await;
    let expected_hash_bytes = download_with_retry(&client, HASH_URL, "server hash").await;
    let expected_hash = String::from_utf8_lossy(&expected_hash_bytes)
        .trim()
        .to_string();

    // ======================================================================
    // STEP 3: COMPUTE HASH AND COMPARE
    // ======================================================================
    let mut ctx384 = Context::new(&SHA384);
    ctx384.update(&app_bytes);
    let runtime_hash = ctx384.finish();
    let hash_hex = base16ct::lower::encode_string(runtime_hash.as_ref());
    println!("[INIT] Payload SHA-384: {}", hash_hex);

    if hash_hex != expected_hash {
        panic_shutdown(&format!(
            "CRITICAL: Hash mismatch! Expected: {}, Computed: {}",
            expected_hash, hash_hex
        ));
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

    // ======================================================================
    // VOLTAGE FAULT INJECTION (INSTRUCTION SKIPPING) MITIGATION
    // ======================================================================
    // By inducing a transient hardware fault, an attacker controlling the 
    // physical motherboard might force the CPU to miscalculate a branch condition
    // or skip an instruction entirely. To mitigate this highly complex attack
    // against the single most sensitive task (server verification), we introduce 
    // structural redundancy by performing the check 3 times.
    let valid1 = std::hint::black_box(verifying_key.verify(&app_bytes, &sig_bytes).is_ok());
    let valid2 = std::hint::black_box(verifying_key.verify(&app_bytes, &sig_bytes).is_ok());
    let valid3 = std::hint::black_box(verifying_key.verify(&app_bytes, &sig_bytes).is_ok());

    if !std::hint::black_box(valid1) || !std::hint::black_box(valid2) || !std::hint::black_box(valid3) {
        panic_shutdown("CRITICAL: Signature verification FAILED!\n\
             Binary does NOT match the trusted signing key.\n\
             System shutting down to prevent execution of untrusted code.");
    }
    println!("[INIT] Signature verification PASSED (3/3 redundant checks).");

    // ======================================================================
    // STEP 5: DEPLOY BINARY TO ISOLATED READ-ONLY TMPFS
    // ======================================================================
    println!("[INIT] Writing verified binary to volatile storage...");
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
    println!("[INIT] Spawning server as child process...");

    fn secure_memory_setup() -> std::io::Result<()> {
        unsafe {
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
            .unwrap_or_else(|e| {
                panic_shutdown(&format!("Failed to spawn attestation server: {}", e))
            })
    };

    let attest_pid = attest_child.id();
    println!(
        "[INIT] Attestation server spawned as isolated PID {}.",
        attest_pid
    );

    println!("[INIT] Boot sequence complete. System operational. PID 1 entering watchdog mode.");

    // PID 1 watchdog & zombie reaper loop
    loop {
        loop {
            let mut status = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid <= 0 {
                break;
            }
            if pid == child_pid as i32 {
                panic_shutdown(&format!(
                    "Server process (PID {}) exited. System integrity compromised.",
                    pid
                ));
            } else if pid == attest_pid as i32 {
                panic_shutdown(&format!(
                    "Attestation server (PID {}) exited. System integrity compromised.",
                    pid
                ));
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}
