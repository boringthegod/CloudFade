use clap::{App, Arg};
use futures::stream::FuturesUnordered;
use futures::stream::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use num_cpus;
use rand::seq::SliceRandom;
use reqwest::header::HeaderMap;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use colored::*;
use scraper::{Html, Selector};

#[tokio::main]
async fn main() {
    let matches = App::new("CloudFade")
        .version("1.4")
        .author("boring")
        .about("Unmask real IP address of a domain hidden behind Cloudflare by IPs bruteforcing")
        .arg(
            Arg::with_name("domain")
                .long("domain")
                .short("d")
                .help("Domain to unmask")
                .required_unless("targetsfile")
                .conflicts_with("targetsfile")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("targetsfile")
                .long("targetsfile")
                .short("t")
                .value_name("TARGETS_FILE")
                .help("File containing list of domains")
                .takes_value(true)
                .conflicts_with("domain")
                .required_unless("domain"),
        )
        .arg(
            Arg::with_name("ipfile")
                .long("ipfile")
                .short("i")
                .help("File containing list of IP addresses")
                .conflicts_with("iprange")
                .required_unless("iprange")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("iprange")
                .long("iprange")
                .value_name("IP_RANGE")
                .help("Specifies a single IP address or a range of IP addresses (e.g., 51.15.0.0-51.15.10.255)")
                .conflicts_with("ipfile")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("useragents")
                .long("useragents")
                .value_name("UA_FILE")
                .help("File containing the list of user agents")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("timeout")
                .long("timeout")
                .value_name("SECONDS")
                .help("Waiting time for each request in seconds")
                .default_value("5"),
        )
        .arg(
            Arg::with_name("aggressive")
                .long("aggressive")
                .help("More intensive checks"),
        )
        .arg(
            Arg::with_name("threads")
                .long("threads")
                .value_name("NUMBER")
                .help("Set the maximum number of concurrent threads")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("output")
                .long("output")
                .value_name("OUTPUT_FILE")
                .help("File to write the results")
                .takes_value(true),
        )
        .get_matches();

    let domains = if let Some(domain) = matches.value_of("domain") {
        vec![domain.to_string()]
    } else if let Some(targets_file) = matches.value_of("targetsfile") {
        read_lines(targets_file)
    } else {
        eprintln!("You must specify either a domain with --domain, or a domain file with --targetsfile.");
        return;
    };

    let ip_file = matches.value_of("ipfile");
    let ip_range = matches.value_of("iprange");
    let ua_file = matches.value_of("useragents");
    let timeout_secs: u64 = matches.value_of("timeout").unwrap().parse().unwrap();
    let timeout_duration = Duration::from_secs(timeout_secs);
    let aggressive = matches.is_present("aggressive");

    let num_cpus = num_cpus::get();
    let default_threads = num_cpus * 10;

    let max_threads = matches
        .value_of("threads")
        .map(|s| s.parse::<usize>().unwrap_or(default_threads))
        .unwrap_or(default_threads);

    println!(
        "Use of : {} threads",
        format!("{}", max_threads).blue()
    );

    let ips = if let Some(ip_file) = ip_file {
        read_lines(ip_file)
    } else if let Some(ip_range_str) = ip_range {
        match parse_ip_range(ip_range_str) {
            Ok(ips) => ips,
            Err(e) => {
                eprintln!("{}", e.red());
                return;
            }
        }
    } else {
        eprintln!("You must specify either an IP address file with --ipfile, or an IP address range with --iprange.");
        return;
    };

    if ips.is_empty() {
        eprintln!("No IP address found.");
        return;
    }

    let filtered_ips = filter_cloudflare_ips(ips).await;
    if filtered_ips.is_empty() {
        eprintln!("No non-Cloudflare IP addresses to process.");
        return;
    }

    let mut valid_domains = Vec::new();
    for domain in &domains {
        if is_domain_valid(domain, timeout_duration).await {
            valid_domains.push(domain.clone());
        } else {
            eprintln!("Ignoring domain {} due to unresponsiveness or invalid status code", domain);
        }
    }

    if valid_domains.is_empty() {
        eprintln!("No valid domains to process.");
        return;
    }

    let total_tasks = valid_domains.len() * filtered_ips.len();

    let pb = ProgressBar::new(total_tasks as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .progress_chars("#>-"),
    );

    let user_agents = if let Some(ua_path) = ua_file {
        let uas = read_lines(ua_path);
        if uas.is_empty() {
            vec!["Mozilla/5.0 (compatible; CloudFade/1.0; +https://example.com)".to_string()]
        } else {
            uas
        }
    } else {
        vec!["Mozilla/5.0 (compatible; CloudFade/1.0; +https://example.com)".to_string()]
    };

    let mut target_patterns = HashMap::new();

    for domain in &valid_domains {
        let target_pattern = match get_target_pattern(domain, timeout_duration).await {
            Some(pattern) => pattern,
            None => {
                eprintln!(
                    "Unable to extract a single pattern from the target domain for {}",
                    domain
                );
                continue;
            }
        };
        target_patterns.insert(domain.clone(), target_pattern);
    }

    if target_patterns.is_empty() {
        eprintln!("No single motif could be extracted from the target domains.");
        return;
    }

    let tasks_list: Vec<(String, String)> = target_patterns
        .keys()
        .flat_map(|domain| filtered_ips.iter().map(move |ip| (domain.clone(), ip.clone())))
        .collect();

    let semaphore = Arc::new(Semaphore::new(max_threads));

    let mut tasks = FuturesUnordered::new();

    let output_file = matches.value_of("output");
    let output_mutex = if let Some(output_path) = output_file {
        Some(Arc::new(tokio::sync::Mutex::new(
            tokio::fs::File::create(output_path).await.unwrap(),
        )))
    } else {
        None
    };

    for (domain, ip) in tasks_list {
        let domain = domain.clone();
        let ip = ip.trim().to_string();
        let user_agents = user_agents.clone();
        let aggressive = aggressive;
        let timeout_duration = timeout_duration;
        let semaphore = semaphore.clone();
        let pb = pb.clone();

        let target_pattern = target_patterns.get(&domain).unwrap().clone();

        let permit = semaphore.clone().acquire_owned().await.unwrap();

        tasks.push(tokio::spawn(async move {
            let result = test_ip(
                ip,
                domain.clone(),
                user_agents,
                aggressive,
                timeout_duration,
                target_pattern.clone(),
            )
            .await;
            drop(permit);
            pb.inc(1);
            result
        }));
    }

    while let Some(result) = tasks.next().await {
        if let Ok(Some((domain, ip))) = result {
            let message = format!("{}: {}", domain.green(), ip.green());
            pb.println(message.clone());

            if let Some(output_mutex) = &output_mutex {
                let mut file = output_mutex.lock().await;
                let line = format!("{}: {}\n", domain, ip);
                file.write_all(line.as_bytes()).await.unwrap();
            }
        }
    }

    pb.finish_with_message("Scan completed");
}

async fn test_ip(
    ip: String,
    domain: String,
    user_agents: Vec<String>,
    aggressive: bool,
    timeout_duration: Duration,
    target_pattern: String,
) -> Option<(String, String)> {
    let socket_addr: SocketAddr = match format!("{}:80", ip).parse() {
        Ok(addr) => addr,
        Err(_) => {
            eprintln!("Invalid IP address : {}", ip);
            return None;
        }
    };

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .resolve(&domain, socket_addr)
        .build()
        .unwrap();

    let protocols = vec!["http", "https"];
    let paths = if aggressive {
        vec!["/", "/404", "/robots.txt", "/license.txt", "/README.md"]
    } else {
        vec!["/", "/404"]
    };

    for protocol in &protocols {
        for path in &paths {
            let url = format!("{}://{}{}", protocol, domain, path);
            let ua = user_agents.choose(&mut rand::thread_rng()).unwrap().clone();

            let mut headers = HeaderMap::new();
            headers.insert("User-Agent", ua.parse().unwrap());

            let request = client.get(&url).headers(headers);

            let response = timeout(timeout_duration, request.send()).await;

            if let Ok(Ok(resp)) = response {
                let status = resp.status().as_u16();
                if status == 200 || status == 301 || status == 302 {
                    if let Ok(text) = resp.text().await {
                        if text.contains(&target_pattern) {
                            return Some((domain, ip));
                        }
                    }
                }
            }
        }
    }
    None
}

async fn is_domain_valid(domain: &str, timeout_duration: Duration) -> bool {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let url = format!("http://{}/", domain);
    let request = client.get(&url);

    let response = timeout(timeout_duration, request.send()).await;
    if let Ok(Ok(resp)) = response {
        let status = resp.status();
        if status == 200 {
            true
        } else {
            eprintln!("Domain {} returned status code {}", domain, status);
            false
        }
    } else {
        eprintln!("Domain {} is unresponsive", domain);
        false
    }
}

async fn get_target_pattern(domain: &str, timeout_duration: Duration) -> Option<String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let url = format!("http://{}/", domain);
    let request = client.get(&url);

    let response = timeout(timeout_duration, request.send()).await;
    if let Ok(Ok(resp)) = response {
        if resp.status() != 200 {
            eprintln!("Domain {} returned status code {}", domain, resp.status());
            return None;
        }
        if let Ok(text) = resp.text().await {
            if let Some(title) = extract_title(&text) {
                return Some(title);
            }
        }
    } else {
        eprintln!("Domain {} is unresponsive", domain);
    }
    None
}

fn extract_title(html: &str) -> Option<String> {
    let document = Html::parse_document(html);
    let selector = Selector::parse("title").unwrap();

    document
        .select(&selector)
        .next()
        .map(|element| element.inner_html())
}

fn read_lines(filename: &str) -> Vec<String> {
    let file = File::open(filename).expect("Unable to open file");
    let reader = BufReader::new(file);
    reader
        .lines()
        .filter_map(Result::ok)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

fn parse_ip_range(ip_range: &str) -> Result<Vec<String>, String> {
    let parts: Vec<&str> = ip_range.split('-').collect();
    if parts.len() == 1 {
        // Traiter comme une seule adresse IP
        let ip = parts[0];
        let ip_addr = Ipv4Addr::from_str(ip).map_err(|_| "Adresse IP invalide.".to_string())?;
        Ok(vec![ip_addr.to_string()])
    } else if parts.len() == 2 {
        // Traiter comme une plage d'adresses IP
        let start_ip =
            Ipv4Addr::from_str(parts[0]).map_err(|_| "Adresse IP de début invalide.".to_string())?;
        let end_ip =
            Ipv4Addr::from_str(parts[1]).map_err(|_| "Adresse IP de fin invalide.".to_string())?;

        let start: u32 = start_ip.into();
        let end: u32 = end_ip.into();

        if start > end {
            return Err("L'adresse IP de début est supérieure à l'adresse IP de fin.".to_string());
        }

        let max_ips = 1_000_000;
        let total_ips = end - start + 1;

        if total_ips > max_ips {
            return Err(format!(
                "La plage d'adresses IP est trop grande ({} adresses). Veuillez spécifier une plage plus petite.",
                total_ips
            ));
        }

        let ips: Vec<String> = (start..=end)
            .map(|ip_num| Ipv4Addr::from(ip_num).to_string())
            .collect();

        Ok(ips)
    } else {
        Err("Format de plage IP invalide. Utilisez le format 'début-fin' ou spécifiez une seule adresse IP.".to_string())
    }
}

async fn filter_cloudflare_ips(ips: Vec<String>) -> Vec<String> {
    let semaphore = Arc::new(Semaphore::new(50));
    let mut tasks = FuturesUnordered::new();
    let asn_to_filter = "AS13335";

    for ip in ips {
        let ip = ip.clone();
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        tasks.push(tokio::spawn(async move {
            let result = is_cloudflare_ip(&ip, asn_to_filter).await;
            drop(permit);
            if !result {
                Some(ip)
            } else {
                None
            }
        }));
    }

    let mut filtered_ips = Vec::new();
    while let Some(result) = tasks.next().await {
        if let Ok(Some(ip)) = result {
            filtered_ips.push(ip);
        }
    }

    filtered_ips
}

async fn is_cloudflare_ip(ip: &str, asn_to_filter: &str) -> bool {
    let output = Command::new("whois")
        .arg(ip)
        .output();

    match output {
        Ok(output) => {
            if output.status.success() {
                let data = String::from_utf8_lossy(&output.stdout).to_lowercase();
                if data.contains(&asn_to_filter.to_lowercase()) {
                    true
                } else {
                    false
                }
            } else {
                eprintln!("WHOIS command failed for IP {}: {}", ip, String::from_utf8_lossy(&output.stderr));
                false
            }
        }
        Err(e) => {
            eprintln!("Failed to execute WHOIS command for IP {}: {}", ip, e);
            false
        }
    }
}
