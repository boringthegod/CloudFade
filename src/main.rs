use clap::{App, Arg, ArgGroup};
use futures::stream::FuturesUnordered;
use futures::stream::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use num_cpus;
use rand::seq::SliceRandom;
use reqwest::header::HeaderMap;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::io::Read;
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
use rquest::tls::Impersonate;
use flate2::read::GzDecoder;
use regex::Regex;
use tokio::process::Command as TokioCommand;
use ipnet::Ipv4Net;

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
                .takes_value(true),
        )
        .arg(
            Arg::with_name("iprange")
                .long("iprange")
                .value_name("IP_RANGE")
                .help("Specifies a single IP address, a range of IP addresses (e.g., 51.15.0.0-51.15.10.255), or a CIDR notation (e.g., 51.15.0.0/16)")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("asn")
                .long("asn")
                .value_name("ASN_CODE")
                .help("Specify an ASN code (e.g., AS714) to scan all ranges associated with it")
                .takes_value(true),
        )
        .group(ArgGroup::with_name("ip_input")
            .args(&["ipfile", "iprange", "asn"])
            .required(true)
            .multiple(false)
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
    let asn_code = matches.value_of("asn");
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
    } else if let Some(asn_code) = asn_code {
        let ranges = fetch_ranges_for_asn(asn_code).await;
        if ranges.is_empty() {
            eprintln!("No IP ranges found for ASN code {}", asn_code);
            return;
        } else {
            println!("Found the following ranges for ASN {}:", asn_code);
            for range in &ranges {
                println!("{}", range);
            }
            let mut ips = Vec::new();
            for range in ranges {
                match parse_ip_range(&range) {
                    Ok(mut range_ips) => ips.append(&mut range_ips),
                    Err(e) => eprintln!("Error parsing range {}: {}", range, e),
                }
            }
            ips
        }
    } else {
        eprintln!("You must specify either an IP address file with --ipfile, an IP address range with --iprange, or an ASN code with --asn.");
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
            return true;
        } else if status == 403 {
            return retry_with_rquest(domain).await;
        } else {
            eprintln!("Domain {} returned status code {}", domain, status);
            return false;
        }
    } else {
        eprintln!("Domain {} is unresponsive", domain);
        return false;
    }
}


async fn retry_with_rquest(domain: &str) -> bool {
    let client2 = match rquest::Client::builder()
        .impersonate(Impersonate::Chrome129)
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Erreur lors de la création du client: {}", e);
            return false;
        }
    };

    let url = format!("https://{}", domain);

    let request_builder = client2.get(&url);
    let request = match request_builder.build() {
        Ok(req) => req,
        Err(e) => {
            eprintln!("Erreur lors de la construction de la requête: {}", e);
            return false;
        }
    };

    let resp = match client2.execute(request).await {
        Ok(response) => response,
        Err(e) => {
            eprintln!("Erreur lors de l'exécution de la requête: {}", e);
            return false;
        }
    };

    let status = resp.status();

    status.is_success()
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
        if resp.status() == 200 {
            if let Ok(text) = resp.text().await {
                if let Some(title) = extract_title(&text) {
                    return Some(title);
                }
            }
        } else if resp.status() == 403 {
            return match fetch_title_with_rquest(domain).await {
                Ok(title) => Some(title),
                Err(e) => {
                    eprintln!("Failed to fetch title via rquest: {}", e);
                    None
                }
            };
        }
    }

    eprintln!("Domain {} is unresponsive or returned an error.", domain);
    None
}

async fn fetch_title_with_rquest(domain: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome129)
        .build()?;

    let url = format!("https://{}/", domain);
    let resp = client.get(&url).send().await?;

    let status = resp.status();
    if status == 200 {
        let body = if let Some(encoding) = resp.headers().get("Content-Encoding") {
            if encoding == "gzip" {
                let body = resp.bytes().await?;
                let mut decoder = GzDecoder::new(&body[..]);
                let mut decompressed_body = String::new();
                decoder.read_to_string(&mut decompressed_body)?;
                decompressed_body
            } else {
                resp.text().await?
            }
        } else {
            resp.text().await?
        };

        let document = Html::parse_document(&body);
        let selector = Selector::parse("title").unwrap();

        if let Some(title_element) = document.select(&selector).next() {
            let title = title_element.inner_html();
            return Ok(title);
        } else {
            return Err("No <title> found.".into());
        }
    } else {
        return Err(format!("Request failed with status: {}", status).into());
    }
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
    if ip_range.contains('/') {
        // Handle CIDR notation
        let cidr = ip_range;
        let ipnet: Ipv4Net = match cidr.parse() {
            Ok(net) => net,
            Err(_) => return Err("Invalid CIDR notation.".to_string()),
        };
        let ips: Vec<String> = ipnet.hosts().map(|ip| ip.to_string()).collect();
        Ok(ips)
    } else if ip_range.contains('-') {
        // Handle start-end format
        let parts: Vec<&str> = ip_range.split('-').collect();
        if parts.len() == 2 {
            let start_ip =
                Ipv4Addr::from_str(parts[0]).map_err(|_| "Invalid start IP address.".to_string())?;
            let end_ip =
                Ipv4Addr::from_str(parts[1]).map_err(|_| "Invalid end IP address.".to_string())?;

            let start: u32 = start_ip.into();
            let end: u32 = end_ip.into();

            if start > end {
                return Err("Start IP address is greater than end IP address.".to_string());
            }

            let ips: Vec<String> = (start..=end)
                .map(|ip_num| Ipv4Addr::from(ip_num).to_string())
                .collect();

            Ok(ips)
        } else {
            Err("Invalid IP range format. Use 'start-end' format, CIDR notation, or specify a single IP address.".to_string())
        }
    } else {
        // Handle single IP address
        let ip = ip_range;
        let ip_addr = Ipv4Addr::from_str(ip).map_err(|_| "Invalid IP address.".to_string())?;
        Ok(vec![ip_addr.to_string()])
    }
}

async fn fetch_ranges_for_asn(asn_code: &str) -> Vec<String> {
    let whois_arg = format!("-i origin {}", asn_code);

    let output = TokioCommand::new("whois")
        .arg("-h")
        .arg("whois.radb.net")
        .arg("--")
        .arg(&whois_arg)
        .output()
        .await;

    match output {
        Ok(output) => {
            if output.status.success() {
                let data = String::from_utf8_lossy(&output.stdout);
                let re = Regex::new(r"(\d{1,3}\.){3}\d{1,3}/\d+").unwrap();
                let mut ranges = Vec::new();
                for cap in re.captures_iter(&data) {
                    let range = cap.get(0).unwrap().as_str().to_string();
                    ranges.push(range);
                }
                ranges
            } else {
                eprintln!("WHOIS command failed for ASN {}: {}", asn_code, String::from_utf8_lossy(&output.stderr));
                Vec::new()
            }
        }
        Err(e) => {
            eprintln!("Failed to execute WHOIS command for ASN {}: {}", asn_code, e);
            Vec::new()
        }
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
