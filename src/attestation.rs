use crate::config::{ATTESTATION_PORT, MAX_CONSECUTIVE_ERRORS};
use crate::panic_shutdown;
use aws_lc_rs::digest::{Context, SHA512};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SNP_GET_REPORT: libc::c_ulong = 0xC020_5300;

#[repr(C)]
struct SnpGuestRequestIoctl {
    msg_version: u8,
    _pad: [u8; 7],
    req_data: u64,
    resp_data: u64,
    exitinfo2: u64,
}

#[repr(C)]
struct SnpReportReq {
    user_data: [u8; 64],
    vmpl: u32,
    _rsvd: [u8; 28],
}

#[repr(C)]
struct SnpReportResp {
    data: [u8; 4000],
}

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
        if let Ok(mut map) = self.limiter.subnets.lock()
            && let Some(state) = map.get_mut(&self.subnet)
        {
            state.active_connections = state.active_connections.saturating_sub(1);
        }
    }
}

pub async fn run_attestation_server(payload_hash_hex: &str) {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", ATTESTATION_PORT))
        .await
        .unwrap_or_else(|e| panic_shutdown(&format!("Failed to bind attestation port: {}", e)));

    println!(
        "[ATTEST] Attestation server bound on :{} — this is the independent watchdog.",
        ATTESTATION_PORT
    );
    println!("[ATTEST] Any failure or interference with this server triggers immediate shutdown.");

    let payload_hash = payload_hash_hex.to_string();
    let mut consecutive_errors: u32 = 0;

    // Limit per subnet (IPv4 /24, IPv6 /64) to prevent organized spam while allowing legitimate load
    let subnet_limiter = Arc::new(PerSubnetLimiter::new(
        10,
        std::time::Duration::from_secs(3),
        2,
    ));
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
                let kind = e.kind();
                if kind == std::io::ErrorKind::ConnectionAborted
                    || kind == std::io::ErrorKind::ConnectionReset
                    || kind == std::io::ErrorKind::BrokenPipe
                    || kind == std::io::ErrorKind::Interrupted
                {
                    continue;
                }

                if e.raw_os_error() == Some(libc::EMFILE) || e.raw_os_error() == Some(libc::ENFILE)
                {
                    eprintln!(
                        "[WARN] Attestation server out of file descriptors (EMFILE/ENFILE). Throttling..."
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    continue;
                }

                consecutive_errors += 1;
                eprintln!(
                    "[ATTEST] Accept error ({}/{}): {}",
                    consecutive_errors, MAX_CONSECUTIVE_ERRORS, e
                );

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
    let _subnet_permit = match subnet_limiter.acquire(ip) {
        Ok(permit) => permit,
        Err("rate_limit_exceeded") => {
            send_http_response(
                &mut stream,
                429,
                "application/json",
                r#"{"error":"too_many_requests","message":"Subnet rate limit exceeded"}"#,
            )
            .await?;
            return Ok(());
        }
        Err(_) => {
            send_http_response(
                &mut stream,
                429,
                "application/json",
                r#"{"error":"too_many_requests","message":"Subnet concurrency limit exceeded"}"#,
            )
            .await?;
            return Ok(());
        }
    };

    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n =
            match tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut chunk))
                .await
            {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => return Ok(()),
            };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
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

    if parts.len() != 3 || parts[0] != "GET" || !parts[2].starts_with("HTTP/") {
        return Ok(());
    }

    let path_query = parts[1];
    if !path_query.starts_with("/v1/attestation") {
        return Ok(());
    }

    let (path, query) = match path_query.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path_query, ""),
    };

    if path != "/v1/attestation" {
        return Ok(());
    }

    let nonce_hex = extract_query_param(query, "nonce").unwrap_or_default();
    if nonce_hex.len() < 2
        || nonce_hex.len() > 256
        || !nonce_hex.len().is_multiple_of(2)
        || !nonce_hex.chars().all(|c| c.is_ascii_hexdigit())
    {
        send_http_response(&mut stream, 400, "application/json",
            r#"{"error":"invalid_nonce","hint":"nonce must be a hex-encoded string between 1 and 128 bytes (2 to 256 hex characters)"}"#).await?;
        return Ok(());
    }

    let nonce_bytes = match base16ct::mixed::decode_vec(nonce_hex) {
        Ok(b) => b,
        Err(_) => return Ok(()),
    };

    let payload_hash_bytes = match base16ct::mixed::decode_vec(payload_hash_hex) {
        Ok(b) => b,
        Err(_) => return Ok(()),
    };

    let mut ctx = Context::new(&SHA512);
    ctx.update(&payload_hash_bytes);
    ctx.update(&nonce_bytes);
    let report_data_hash = ctx.finish();
    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(report_data_hash.as_ref());

    let _hardware_permit = match global_hardware_limiter.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            send_http_response(
                &mut stream,
                503,
                "application/json",
                r#"{"error":"server_busy","message":"Hardware attestation queue is full"}"#,
            )
            .await?;
            return Ok(());
        }
    };

    use base64ct::{Base64Url, Encoding};
    let (report_b64, platform) = match get_snp_attestation_report(&report_data) {
        Ok(report) => (Base64Url::encode_string(&report), "amd-sev-snp"),
        Err(err) => {
            let body = format!(
                r#"{{"error":"snp_unavailable","message":"{}","payload_sha384":"{}","nonce":"{}"}}"#,
                err.replace('"', "'"),
                payload_hash_hex,
                nonce_hex
            );
            send_http_response(&mut stream, 503, "application/json", &body).await?;
            return Ok(());
        }
    };

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
        if let Some((k, v)) = pair.split_once('=')
            && k == key
        {
            return Some(v);
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
        429 => "Too Many Requests",
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
        status,
        status_text,
        content_type,
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    stream.shutdown().await?;
    Ok(())
}

fn get_snp_attestation_report(report_data: &[u8; 64]) -> Result<Vec<u8>, String> {
    let dev_path = "/dev/sev-guest";
    if !Path::new(dev_path).exists() {
        return Err("SEV-SNP device not available (/dev/sev-guest not found)".to_string());
    }

    let fd =
        std::fs::File::open(dev_path).map_err(|e| format!("Failed to open {}: {}", dev_path, e))?;

    let mut req = SnpReportReq {
        user_data: *report_data,
        vmpl: 0,
        _rsvd: [0u8; 28],
    };

    let mut resp = SnpReportResp { data: [0u8; 4000] };

    let mut ioctl_req = SnpGuestRequestIoctl {
        msg_version: 1,
        _pad: [0u8; 7],
        req_data: &mut req as *mut SnpReportReq as u64,
        resp_data: &mut resp as *mut SnpReportResp as u64,
        exitinfo2: 0,
    };

    use std::os::unix::io::AsRawFd;
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), SNP_GET_REPORT as _, &mut ioctl_req) };

    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        return Err(format!(
            "SNP_GET_REPORT ioctl failed: {} (fw_err: {})",
            errno,
            ioctl_req.exitinfo2 & 0xFFFF_FFFF
        ));
    }

    Ok(resp.data[..1184].to_vec())
}
