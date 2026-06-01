use crate::time::parse_http_date;
use reqwest::dns::{Name, Resolve, Resolving};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub struct CustomDohResolver {
    pub doh_client: reqwest::Client,
}

impl Resolve for CustomDohResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let domain = name.as_str().to_string();
        let doh_client = self.doh_client.clone();

        Box::pin(async move {
            println!("[DNS] Resolving {} via DoH...", domain);
            let q = build_a_record_query(&domain);
            let mut res_opt = doh_client
                .post("https://dns.mullvad.net/dns-query")
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
            while let Some(chunk) =
                res_opt
                    .chunk()
                    .await
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                        println!("[DNS] DoH body read failed: {:?}", e);
                        Box::new(e)
                    })?
            {
                if res.len() + chunk.len() > 65536 {
                    println!("[DNS] DoH response too large");
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "DoH response too large",
                    ))
                        as Box<dyn std::error::Error + Send + Sync>);
                }
                res.extend_from_slice(&chunk);
            }

            let ip = parse_dns_response(&res).ok_or_else(
                || -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "No A record found via DoH",
                    ))
                },
            )?;
            println!("[DNS] {} -> {}", domain, ip);

            let addrs: Box<dyn Iterator<Item = SocketAddr> + Send> =
                Box::new(std::iter::once(SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

pub fn build_a_record_query(domain: &str) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&[
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    for part in domain.split('.') {
        query.push(part.len() as u8);
        query.extend_from_slice(part.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    query
}

pub fn parse_dns_response(data: &[u8]) -> Option<IpAddr> {
    if data.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let mut offset = 12;
    // skip question
    while offset < data.len() && data[offset] != 0 {
        offset += data[offset] as usize + 1;
    }
    offset += 1 + 4; // null byte + QTYPE + QCLASS
    for _ in 0..ancount {
        if offset + 12 > data.len() {
            break;
        }
        if data[offset] & 0xC0 == 0xC0 {
            offset += 2;
        } else {
            while offset < data.len() && data[offset] != 0 {
                if data[offset] & 0xC0 == 0xC0 {
                    offset += 2;
                    break;
                }
                offset += data[offset] as usize + 1;
            }
            if offset < data.len() && data[offset] == 0 {
                offset += 1;
            }
        }
        if offset + 10 > data.len() {
            break;
        }
        let atype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;
        if atype == 1 && rdlength == 4 && offset + 4 <= data.len() {
            return Some(IpAddr::V4(Ipv4Addr::new(
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            )));
        }
        offset += rdlength;
    }
    None
}

pub async fn resolve_domain_via_doh(
    doh_client: &reqwest::Client,
    domain: &str,
) -> Result<(IpAddr, Option<u64>), String> {
    let q = build_a_record_query(domain);
    let mut res_opt = doh_client
        .post("https://dns.mullvad.net/dns-query")
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(q)
        .send()
        .await
        .map_err(|e| format!("DoH query failed: {:?}", e))?;

    // Extract Date header for secure fallback time
    let date_timestamp = if let Some(date_val) = res_opt.headers().get(reqwest::header::DATE) {
        if let Ok(date_str) = date_val.to_str() {
            parse_http_date(date_str)
        } else {
            None
        }
    } else {
        None
    };

    let mut res = Vec::new();
    while let Some(chunk) = res_opt
        .chunk()
        .await
        .map_err(|e| format!("DoH body read failed: {:?}", e))?
    {
        if res.len() + chunk.len() > 65536 {
            return Err("DoH response too large".to_string());
        }
        res.extend_from_slice(&chunk);
    }

    let ip = parse_dns_response(&res).ok_or_else(|| "No A record found via DoH".to_string())?;
    Ok((ip, date_timestamp))
}

pub async fn query_mullvad_secure_date(
    doh_client: &reqwest::Client,
    tls_config: rustls::ClientConfig,
) -> Option<u64> {
    // 1. Resolve am.i.mullvad.net via DoH
    let ip = match resolve_domain_via_doh(doh_client, "am.i.mullvad.net").await {
        Ok((ip, _)) => ip,
        Err(e) => {
            eprintln!(
                "[WARN] DoH resolution for am.i.mullvad.net failed: {}. Using hardcoded fallback IP.",
                e
            );
            // Fallback to a known static IP of am.i.mullvad.net
            IpAddr::V4(Ipv4Addr::new(45, 83, 223, 233))
        }
    };

    println!(
        "[TIME] Querying secure Date header fallback from am.i.mullvad.net ({})...",
        ip
    );
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .use_preconfigured_tls(tls_config)
        .resolve("am.i.mullvad.net", SocketAddr::new(ip, 443))
        .build()
    {
        Ok(c) => c,
        Err(_) => return None,
    };

    let res = match client.get("https://am.i.mullvad.net/").send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "[WARN] Date fallback request to am.i.mullvad.net failed: {:?}",
                e
            );
            return None;
        }
    };

    let date_val = res.headers().get(reqwest::header::DATE)?;
    let date_str = date_val.to_str().ok()?;
    parse_http_date(date_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_a_record_query() {
        let query = build_a_record_query("github.com");
        // Header (12 bytes)
        assert_eq!(
            &query[0..12],
            &[
                0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
        // Question: 6 "github" 3 "com" 0
        assert_eq!(query[12], 6);
        assert_eq!(&query[13..19], b"github");
        assert_eq!(query[19], 3);
        assert_eq!(&query[20..23], b"com");
        assert_eq!(query[23], 0);
        // Type A, Class IN
        assert_eq!(&query[24..28], &[0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn test_parse_dns_response_valid() {
        let mut response = Vec::new();
        // Header: Transaction ID (0xabcd), Flags (0x8180), QDCOUNT (1), ANCOUNT (1)
        response.extend_from_slice(&[
            0xab, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        // Question: github.com
        response.extend_from_slice(&[6]);
        response.extend_from_slice(b"github");
        response.extend_from_slice(&[3]);
        response.extend_from_slice(b"com");
        response.extend_from_slice(&[0]);
        // QTYPE (A), QCLASS (IN)
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // Answer: Pointer to name (0xc00c), TYPE (A), CLASS (IN), TTL (60), RDLENGTH (4), RDATA (140.82.121.4)
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
        response.extend_from_slice(&[0x00, 0x04]);
        response.extend_from_slice(&[140, 82, 121, 4]);

        let parsed = parse_dns_response(&response).expect("Should parse valid DNS response");
        assert_eq!(parsed, IpAddr::V4(Ipv4Addr::new(140, 82, 121, 4)));
    }

    #[test]
    fn test_parse_dns_response_truncated() {
        // Empty or header only
        assert!(parse_dns_response(&[]).is_none());
        assert!(parse_dns_response(&[0; 10]).is_none());

        let mut response = Vec::new();
        response.extend_from_slice(&[
            0xab, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        response.extend_from_slice(&[6]);
        response.extend_from_slice(b"github");
        response.extend_from_slice(&[3]);
        response.extend_from_slice(b"com");
        response.extend_from_slice(&[0]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // Truncated Answer
        response.extend_from_slice(&[0xc0, 0x0c]);
        assert!(parse_dns_response(&response).is_none());
    }
}
