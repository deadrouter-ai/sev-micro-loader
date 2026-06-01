use aws_lc_rs::digest::{Context, SHA512};
use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use base64ct::{Base64, Encoding};
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug)]
pub struct RoughtimeServer {
    pub name: &'static str,
    pub host: &'static str,
    pub port: u16,
    pub pubkey_base64: &'static str,
}

pub const ROUGHTIME_SERVERS: &[RoughtimeServer] = &[
    RoughtimeServer {
        name: "cloudflare",
        host: "roughtime.cloudflare.com",
        port: 2003,
        pubkey_base64: "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg=",
    },
    RoughtimeServer {
        name: "roughtime.se",
        host: "roughtime.se",
        port: 2002,
        pubkey_base64: "S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI=",
    },
    RoughtimeServer {
        name: "roughtime.int08h.com",
        host: "roughtime.int08h.com",
        port: 2002,
        pubkey_base64: "AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=",
    },
    RoughtimeServer {
        name: "sth1.roughtime.netnod.se",
        host: "sth1.roughtime.netnod.se",
        port: 2002,
        pubkey_base64: "9l1JN4HakGnG44yyqyNNCb0HN0XfsysBbnl/kbZoZDc=",
    },
    RoughtimeServer {
        name: "sth2.roughtime.netnod.se",
        host: "sth2.roughtime.netnod.se",
        port: 2002,
        pubkey_base64: "T/xxX4ERUBAOpt64Z8phWamKsASZxJ0VWuiPm3GS/8g=",
    },
    RoughtimeServer {
        name: "rough.time.nl",
        host: "rough.time.nl",
        port: 2002,
        pubkey_base64: "v2CievhgKsxzlWPwIkYFUXeA51Akhkv5uhJCj1/kbiY=",
    },
    RoughtimeServer {
        name: "time.teax.dev",
        host: "time.teax.dev",
        port: 2002,
        pubkey_base64: "84pMADvKUcSOq5RNbVRjVrjiU16Dxo2XV2Qkm+4DRTg=",
    },
    RoughtimeServer {
        name: "roughtime.sturdystatistics.com",
        host: "roughtime.sturdystatistics.com",
        port: 2002,
        pubkey_base64: "NqIjwLopQn6yQChtE21Mb97dAbAPe5UOuTa0tOakgD8=",
    },
    RoughtimeServer {
        name: "ilimit-rt01.ilimit.cat",
        host: "ilimit-rt01.ilimit.cat",
        port: 2002,
        pubkey_base64: "Oj8AxjzCYMlBicllTdeiJOEluLHdxijGd6sSaS993eo=",
    },
    RoughtimeServer {
        name: "ilimit-rt02.ilimit.cat",
        host: "ilimit-rt02.ilimit.cat",
        port: 2002,
        pubkey_base64: "XTNZR7TIw4iMV2mNOVNPYzmWxXxg1DA16o2SYLp1k8k=",
    },
];

pub const LAST_KNOWN_GOOD_TIME_SECS: u64 = 1_780_272_000; // June 1, 2026 00:00:00 UTC
pub const LAST_KNOWN_GOOD_TIME_MICROS: u64 = 1_780_272_000_001_000;

pub const TAG_NONC: u32 = 0x434e4f4e; // b"NONC"
pub const TAG_PAD: u32 = 0xff444150; // b"PAD\xff"
pub const TAG_CERT: u32 = 0x54524543; // b"CERT"
pub const TAG_SIG: u32 = 0x00474953; // b"SIG\x00"
pub const TAG_SREP: u32 = 0x50455253; // b"SREP"
pub const TAG_DELE: u32 = 0x454c4544; // b"DELE"
pub const TAG_PUBK: u32 = 0x4b425550; // b"PUBK"
pub const TAG_MINT: u32 = 0x544e494d; // b"MINT"
pub const TAG_MAXT: u32 = 0x5458414d; // b"MAXT"
pub const TAG_ROOT: u32 = 0x544f4f52; // b"ROOT"
pub const TAG_MIDP: u32 = 0x5044494d; // b"MIDP"
pub const TAG_RADI: u32 = 0x49444152; // b"RADI"
pub const TAG_INDX: u32 = 0x58444e49; // b"INDX"
pub const TAG_PATH: u32 = 0x48544150; // b"PATH"

pub struct RtMessage {
    pub tags: Vec<u32>,
    pub values: Vec<Vec<u8>>,
}

impl RtMessage {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let num_tags = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if num_tags == 0 {
            return None;
        }
        let header_len = 8 * num_tags;
        if data.len() < header_len {
            return None;
        }

        let mut offsets = Vec::with_capacity(num_tags);
        offsets.push(0); // first value starts at offset 0
        for i in 0..num_tags.saturating_sub(1) {
            let idx = 4 + i * 4;
            offsets.push(u32::from_le_bytes([
                data[idx],
                data[idx + 1],
                data[idx + 2],
                data[idx + 3],
            ]) as usize);
        }

        let mut tags = Vec::with_capacity(num_tags);
        let tags_start = 4 + num_tags.saturating_sub(1) * 4;
        for i in 0..num_tags {
            let idx = tags_start + i * 4;
            tags.push(u32::from_le_bytes([
                data[idx],
                data[idx + 1],
                data[idx + 2],
                data[idx + 3],
            ]));
        }

        let values_start = 8 * num_tags;
        let values_len = data.len() - values_start;
        let values_data = &data[values_start..];

        // Validate offsets are in-bounds and increasing and multiples of 4
        for i in 0..num_tags {
            let start = offsets[i];
            let end = if i + 1 < num_tags {
                offsets[i + 1]
            } else {
                values_len
            };
            if start > end || end > values_len {
                return None;
            }
            if start % 4 != 0 || end % 4 != 0 {
                return None;
            }
        }

        let mut values = Vec::with_capacity(num_tags);
        for i in 0..num_tags {
            let start = offsets[i];
            let end = if i + 1 < num_tags {
                offsets[i + 1]
            } else {
                values_len
            };
            values.push(values_data[start..end].to_vec());
        }

        Some(Self { tags, values })
    }

    pub fn get(&self, tag: u32) -> Option<&[u8]> {
        for (i, t) in self.tags.iter().enumerate() {
            if *t == tag {
                return Some(&self.values[i]);
            }
        }
        None
    }
}

pub fn verify_roughtime_response(
    data: &[u8],
    nonce: &[u8; 64],
    pubkey_base64: &str,
) -> Result<u64, String> {
    let resp = RtMessage::parse(data).ok_or("Invalid top-level Roughtime response".to_string())?;
    let cert_bytes = resp
        .get(TAG_CERT)
        .ok_or("Missing CERT in response".to_string())?;
    let srep_bytes = resp
        .get(TAG_SREP)
        .ok_or("Missing SREP in response".to_string())?;
    let sig_bytes = resp
        .get(TAG_SIG)
        .ok_or("Missing SIG in response".to_string())?;

    // Parse CERT
    let cert = RtMessage::parse(cert_bytes).ok_or("Invalid CERT message".to_string())?;
    let dele_bytes = cert
        .get(TAG_DELE)
        .ok_or("Missing DELE in CERT".to_string())?;
    let cert_sig_bytes = cert.get(TAG_SIG).ok_or("Missing SIG in CERT".to_string())?;

    // Verify delegation signature
    let root_pubkey_bytes = Base64::decode_vec(pubkey_base64)
        .map_err(|_| format!("Failed to decode root public key: {}", pubkey_base64))?;

    let root_key = UnparsedPublicKey::new(&ED25519, &root_pubkey_bytes);
    let mut dele_signed_data = Vec::with_capacity(36 + dele_bytes.len());
    dele_signed_data.extend_from_slice(b"RoughTime v1 delegation signature--\x00");
    dele_signed_data.extend_from_slice(dele_bytes);

    root_key
        .verify(&dele_signed_data, cert_sig_bytes)
        .map_err(|e| format!("Failed to verify delegation signature: {:?}", e))?;

    // Parse DELE
    let dele = RtMessage::parse(dele_bytes).ok_or("Invalid DELE message".to_string())?;
    let online_pubkey = dele
        .get(TAG_PUBK)
        .ok_or("Missing PUBK in DELE".to_string())?;
    let mint_bytes = dele
        .get(TAG_MINT)
        .ok_or("Missing MINT in DELE".to_string())?;
    let maxt_bytes = dele
        .get(TAG_MAXT)
        .ok_or("Missing MAXT in DELE".to_string())?;

    let mint = u64::from_le_bytes(
        mint_bytes
            .try_into()
            .map_err(|_| "Invalid MINT size".to_string())?,
    );
    let maxt = u64::from_le_bytes(
        maxt_bytes
            .try_into()
            .map_err(|_| "Invalid MAXT size".to_string())?,
    );

    // Verify response signature using online key
    let online_key = UnparsedPublicKey::new(&ED25519, online_pubkey);
    let mut srep_signed_data = Vec::with_capacity(32 + srep_bytes.len());
    srep_signed_data.extend_from_slice(b"RoughTime v1 response signature\x00");
    srep_signed_data.extend_from_slice(srep_bytes);

    online_key
        .verify(&srep_signed_data, sig_bytes)
        .map_err(|e| format!("Failed to verify response signature: {:?}", e))?;

    // Parse SREP
    let srep = RtMessage::parse(srep_bytes).ok_or("Invalid SREP message".to_string())?;
    let root_hash = srep
        .get(TAG_ROOT)
        .ok_or("Missing ROOT in SREP".to_string())?;
    let midpoint_bytes = srep
        .get(TAG_MIDP)
        .ok_or("Missing MIDP in SREP".to_string())?;
    let radius_bytes = srep
        .get(TAG_RADI)
        .ok_or("Missing RADI in SREP".to_string())?;

    let midpoint = u64::from_le_bytes(
        midpoint_bytes
            .try_into()
            .map_err(|_| "Invalid MIDP size".to_string())?,
    );
    let _radius = u32::from_le_bytes(
        radius_bytes
            .try_into()
            .map_err(|_| "Invalid RADI size".to_string())?,
    );

    // Verify delegation validity interval
    if midpoint < mint || midpoint > maxt {
        return Err(format!(
            "Delegation key not valid at midpoint (midpoint={}, mint={}, maxt={})",
            midpoint, mint, maxt
        ));
    }

    // Verify Merkle path
    let index_bytes = resp
        .get(TAG_INDX)
        .ok_or("Missing INDX in response".to_string())?;
    let path_bytes = resp
        .get(TAG_PATH)
        .ok_or("Missing PATH in response".to_string())?;

    let index = u32::from_le_bytes(
        index_bytes
            .try_into()
            .map_err(|_| "Invalid INDX size".to_string())?,
    );
    if path_bytes.len() % 32 != 0 {
        return Err("Invalid PATH length (not multiple of 32)".to_string());
    }

    // Compute leaf hash: SHA-512(0x00 || nonce), truncated to 32 bytes
    let mut hasher = Context::new(&SHA512);
    hasher.update(&[0x00]);
    hasher.update(nonce);
    let full_hash = hasher.finish();
    let mut current_hash = full_hash.as_ref()[0..32].to_vec();

    let mut idx = index;
    for sibling in path_bytes.chunks_exact(32) {
        let mut node_hasher = Context::new(&SHA512);
        node_hasher.update(&[0x01]);
        if idx & 1 == 0 {
            node_hasher.update(&current_hash);
            node_hasher.update(sibling);
        } else {
            node_hasher.update(sibling);
            node_hasher.update(&current_hash);
        }
        let step_hash = node_hasher.finish();
        current_hash = step_hash.as_ref()[0..32].to_vec();
        idx >>= 1;
    }

    if root_hash.len() < 32 {
        return Err("Invalid ROOT hash length".to_string());
    }
    if current_hash != root_hash[0..32] {
        return Err("Merkle proof root mismatch".to_string());
    }

    // Verify index is completely consumed
    if idx != 0 {
        return Err("Merkle index out of bounds for the path depth".to_string());
    }

    Ok(midpoint)
}

pub async fn query_roughtime(
    resolved_servers: Vec<(RoughtimeServer, IpAddr)>,
) -> Result<u64, String> {
    let mut handles = Vec::new();
    for (srv, ip) in resolved_servers {
        let handle = tokio::spawn(async move {
            let res = query_single_roughtime(ip, srv.port, srv.pubkey_base64).await;
            (srv.name, res)
        });
        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok((name, res)) = handle.await {
            results.push((name, res));
        }
    }

    let mut valid_midpoints = Vec::new();
    for (name, res) in results {
        match res {
            Ok(midpoint) => {
                println!(
                    "[TIME] Successful Roughtime response from {}: {}s",
                    name,
                    midpoint / 1_000_000
                );
                valid_midpoints.push(midpoint);
            }
            Err(e) => {
                eprintln!("[WARN] Roughtime query to {} failed: {}", name, e);
            }
        }
    }

    if valid_midpoints.is_empty() {
        return Err("No valid Roughtime responses received from any server".to_string());
    }

    // Sort and calculate the median of midpoints
    valid_midpoints.sort_unstable();
    let median = if valid_midpoints.len() % 2 == 1 {
        valid_midpoints[valid_midpoints.len() / 2]
    } else {
        let mid = valid_midpoints.len() / 2;
        (valid_midpoints[mid - 1] + valid_midpoints[mid]) / 2
    };

    // Check consistency: if difference between min and max midpoints is > 15s, warn
    if valid_midpoints.len() > 1 {
        let diff = valid_midpoints.last().unwrap() - valid_midpoints.first().unwrap();
        if diff > 15_000_000 {
            eprintln!(
                "[WARN] Inconsistent times detected between Roughtime servers! Diff: {}s",
                diff / 1_000_000
            );
        }
    }

    println!(
        "[TIME] Consensus Roughtime established from {} server(s). Median midpoint: {}s",
        valid_midpoints.len(),
        median / 1_000_000
    );
    Ok(median)
}

pub async fn query_single_roughtime(
    ip: IpAddr,
    port: u16,
    pubkey_base64: &str,
) -> Result<u64, String> {
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;
    let server_addr = SocketAddr::new(ip, port);

    // Generate 64-byte random nonce
    let mut nonce = [0u8; 64];
    aws_lc_rs::rand::fill(&mut nonce).map_err(|e| format!("Entropy read failed: {:?}", e))?;

    let mut req = Vec::with_capacity(1024);
    req.extend_from_slice(&2u32.to_le_bytes()); // num_tags
    req.extend_from_slice(&64u32.to_le_bytes()); // offset of tag 1
    req.extend_from_slice(&TAG_NONC.to_le_bytes()); // TAG NONC
    req.extend_from_slice(&TAG_PAD.to_le_bytes()); // TAG PAD
    req.extend_from_slice(&nonce);
    req.resize(1024, 0); // pad to 1024 bytes

    // Send request with retry (2 attempts)
    let mut buf = vec![0u8; 2048];
    let mut received = false;
    let mut n = 0;

    for _attempt in 1..=2 {
        if let Err(e) = socket.send_to(&req, server_addr).await {
            eprintln!("[WARN] Failed to send Roughtime query to {}: {}", ip, e);
            tokio::time::sleep(Duration::from_millis(300)).await;
            continue;
        }

        match timeout(Duration::from_millis(15000), socket.recv_from(&mut buf)).await {
            Ok(Ok((bytes_recvd, _src))) => {
                n = bytes_recvd;
                received = true;
                break;
            }
            Ok(Err(e)) => {
                eprintln!("[WARN] Roughtime receive error: {}", e);
            }
            Err(_) => {
                eprintln!("[WARN] Roughtime query to {} timed out", ip);
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    if !received {
        return Err("Query timed out or failed".to_string());
    }

    let response_data = &buf[..n];

    // Parse and verify response
    let midpoint = verify_roughtime_response(response_data, &nonce, pubkey_base64)?;
    Ok(midpoint)
}

pub fn enforce_time_floor() {
    let now = std::time::SystemTime::now();
    let secs = now
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs();
    if secs < LAST_KNOWN_GOOD_TIME_SECS {
        println!(
            "[TIME] System clock ({}s) is before last known good time ({}s). Enforcing time floor...",
            secs, LAST_KNOWN_GOOD_TIME_SECS
        );
        let ts = libc::timespec {
            tv_sec: LAST_KNOWN_GOOD_TIME_SECS as _,
            tv_nsec: 1_000_000, // 1 millisecond
        };
        unsafe {
            if libc::clock_settime(libc::CLOCK_REALTIME, &ts) != 0 {
                eprintln!("[WARN] Failed to set system clock to last known good time floor.");
            } else {
                println!("[TIME] System clock updated to floor.");
            }
        }
    }
}

pub fn parse_http_date(date_str: &str) -> Option<u64> {
    // Expected format: "Mon, 01 Jun 2026 12:41:36 GMT"
    let mut parts = date_str.split_whitespace();
    let _day_name = parts.next()?; // "Mon,"
    let day_str = parts.next()?; // "01"
    let month_str = parts.next()?; // "Jun"
    let year_str = parts.next()?; // "2026"
    let time_str = parts.next()?; // "12:41:36"

    let day = day_str.parse::<u64>().ok()?;
    let year = year_str.parse::<u64>().ok()?;

    let month = match month_str {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };

    let mut time_parts = time_str.split(':');
    let hour = time_parts.next()?.parse::<u64>().ok()?;
    let minute = time_parts.next()?.parse::<u64>().ok()?;
    let second = time_parts.next()?.parse::<u64>().ok()?;

    // Convert to Unix timestamp
    let mut days = 0;
    for y in 1970..year {
        if is_leap_year(y) {
            days += 366;
        } else {
            days += 365;
        }
    }

    let month_days = if is_leap_year(year) {
        [0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    for m in 1..month {
        days += month_days[m as usize];
    }
    days += day - 1;

    let timestamp = days * 86400 + hour * 3600 + minute * 60 + second;
    Some(timestamp)
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rt_message_parse() {
        let mut msg_data = Vec::new();
        msg_data.extend_from_slice(&2u32.to_le_bytes()); // num_tags
        msg_data.extend_from_slice(&4u32.to_le_bytes()); // offsets (offset of second value is 4)
        msg_data.extend_from_slice(&TAG_NONC.to_le_bytes()); // Tag 1
        msg_data.extend_from_slice(&TAG_PAD.to_le_bytes()); // Tag 2
        msg_data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // Value 1
        msg_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Value 2

        let parsed = RtMessage::parse(&msg_data).expect("Should parse message");
        assert_eq!(parsed.tags.len(), 2);
        assert_eq!(parsed.tags[0], TAG_NONC);
        assert_eq!(parsed.tags[1], TAG_PAD);
        assert_eq!(parsed.get(TAG_NONC).unwrap(), &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(parsed.get(TAG_PAD).unwrap(), &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_merkle_verification() {
        let nonce = [0x55u8; 64];

        let mut hasher = Context::new(&SHA512);
        hasher.update(&[0x00]);
        hasher.update(&nonce);
        let leaf_hash = hasher.finish().as_ref()[0..32].to_vec();

        let mut current_hash = leaf_hash.clone();
        let sibling = vec![0xaa; 32];
        let path = sibling.clone();
        let index = 0u32;

        let mut idx = index;
        for sib in path.chunks_exact(32) {
            let mut node_hasher = Context::new(&SHA512);
            node_hasher.update(&[0x01]);
            if idx & 1 == 0 {
                node_hasher.update(&current_hash);
                node_hasher.update(sib);
            } else {
                node_hasher.update(sib);
                node_hasher.update(&current_hash);
            }
            current_hash = node_hasher.finish().as_ref()[0..32].to_vec();
            idx >>= 1;
        }

        let mut expected_hasher = Context::new(&SHA512);
        expected_hasher.update(&[0x01]);
        expected_hasher.update(&leaf_hash);
        expected_hasher.update(&sibling);
        let expected = expected_hasher.finish().as_ref()[0..32].to_vec();

        assert_eq!(current_hash, expected);
        assert_eq!(idx, 0);
    }

    #[test]
    fn test_is_leap_year() {
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2004));
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(2021));
        assert!(is_leap_year(2024));
    }

    #[test]
    fn test_parse_http_date_valid() {
        let ts = parse_http_date("Mon, 01 Jun 2026 12:41:36 GMT").expect("Parse June 1 2026");
        assert_eq!(ts, 1780317696);

        let ts2 = parse_http_date("Tue, 02 Jun 2026 00:00:00 GMT").expect("Parse June 2 2026");
        assert_eq!(ts2, 1780358400);
    }

    #[test]
    fn test_parse_http_date_invalid() {
        assert!(parse_http_date("Mon, 01 Invalid 2026 12:41:36 GMT").is_none());
        assert!(parse_http_date("Mon, 01 Jun 2026 12:41 GMT").is_none());
        assert!(parse_http_date("").is_none());
    }

    #[test]
    fn test_live_roughtime() {
        use std::net::UdpSocket;
        use std::time::Duration;

        let server_addr = "162.159.200.1:2003";
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(_) => return,
        };
        if socket.set_read_timeout(Some(Duration::from_secs(15))).is_err() {
            return;
        }

        let mut nonce = [0u8; 64];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }

        let mut req = Vec::with_capacity(1024);
        req.extend_from_slice(&2u32.to_le_bytes()); // num_tags
        req.extend_from_slice(&64u32.to_le_bytes()); // offset
        req.extend_from_slice(&TAG_NONC.to_le_bytes()); // NONC
        req.extend_from_slice(&TAG_PAD.to_le_bytes()); // PAD
        req.extend_from_slice(&nonce);
        req.resize(1024, 0);

        if socket.send_to(&req, server_addr).is_err() {
            return;
        }

        let mut buf = vec![0u8; 2048];
        match socket.recv_from(&mut buf) {
            Ok((n, _)) => {
                let resp_data = &buf[..n];
                let resp = RtMessage::parse(resp_data).unwrap();
                let srep = RtMessage::parse(resp.get(TAG_SREP).unwrap()).unwrap();
                let root = srep.get(TAG_ROOT).unwrap();
                let index = u32::from_le_bytes(resp.get(TAG_INDX).unwrap().try_into().unwrap());
                let path = resp.get(TAG_PATH).unwrap();

                let mut current_hash = {
                    let mut hasher = Context::new(&SHA512);
                    hasher.update(&[0x00]);
                    hasher.update(&nonce);
                    hasher.finish().as_ref()[0..32].to_vec()
                };
                let mut idx = index;
                for sibling in path.chunks_exact(32) {
                    let mut node_hasher = Context::new(&SHA512);
                    node_hasher.update(&[0x01]);
                    if idx & 1 == 0 {
                        node_hasher.update(&current_hash);
                        node_hasher.update(sibling);
                    } else {
                        node_hasher.update(sibling);
                        node_hasher.update(&current_hash);
                    }
                    current_hash = node_hasher.finish().as_ref()[0..32].to_vec();
                    idx >>= 1;
                }

                assert_eq!(current_hash, root[0..32]);
            }
            Err(_) => {
                // If live network queries are blocked on the test host, we ignore the error
            }
        }
    }
}
