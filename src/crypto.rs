use crate::config::{MAX_DOWNLOAD_RETRIES, RETRY_DELAY_SECS};
use crate::panic_shutdown;
use std::io::Read;

pub fn wait_for_entropy() {
    println!("[INIT] Waiting for kernel entropy pool (CRNG) to initialize...");
    let mut file = match std::fs::File::open("/dev/random") {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "[WARN] Failed to open /dev/random: {}. Continuing anyway...",
                e
            );
            return;
        }
    };
    let mut buf = [0u8; 1];
    if let Err(e) = file.read_exact(&mut buf) {
        eprintln!(
            "[WARN] Failed to read from /dev/random: {}. Continuing anyway...",
            e
        );
    } else {
        println!("[INIT] Entropy pool ready.");
    }
}

pub async fn download_with_retry(client: &reqwest::Client, url: &str, desc: &str) -> Vec<u8> {
    let mut last_error = String::new();

    for attempt in 1..=MAX_DOWNLOAD_RETRIES {
        if attempt > 1 {
            println!(
                "[INIT] Retry {}/{} for {}...",
                attempt, MAX_DOWNLOAD_RETRIES, desc
            );
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
    panic_shutdown(&format!(
        "Failed to download {} after {} attempts: {}",
        desc, MAX_DOWNLOAD_RETRIES, last_error
    ))
}
