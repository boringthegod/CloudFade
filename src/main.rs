use clap::{App, Arg};
use futures::stream::FuturesUnordered;
use futures::stream::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use num_cpus;
use rand::seq::SliceRandom;
use reqwest::header::HeaderMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use colored::*;
use scraper::{Html, Selector};

#[tokio::main]
async fn main() {
    let matches = App::new("CloudFade")
        .version("1.0")
        .author("boring")
        .about("Unmask real IP address of a domain hidden behind Cloudflare by IPs bruteforcing")
        .arg(
            Arg::with_name("domain")
                .help("Domain to unmask")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("ipfile")
                .help("File containing list of IP addresses")
                .conflicts_with("iprange")
                .required_unless("iprange")
                .index(2),
        )
        .arg(
            Arg::with_name("iprange")
                .long("iprange")
                .value_name("IP_RANGE")
                .help("Specifies a range of IP addresses (for example, 51.15.0.0-51.15.10.255)")
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
        .get_matches();

    let domain = matches.value_of("domain").unwrap();
    let ip_file = matches.value_of("ipfile");
    let ip_range = matches.value_of("iprange");
    let ua_file = matches.value_of("useragents");
    let timeout_secs: u64 = matches.value_of("timeout").unwrap().parse().unwrap();
    let timeout_duration = Duration::from_secs(timeout_secs);
    let aggressive = matches.is_present("aggressive");

    let available_threads = num_cpus::get();

    let max_threads = matches
        .value_of("threads")
        .map(|s| s.parse::<usize>().unwrap_or(available_threads))
        .unwrap_or(available_threads);

    println!(
        "Utilisation de : {} threads",
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
        eprintln!("Vous devez spécifier soit un fichier d'adresses IP, soit une plage d'adresses IP.");
        return;
    };

    if ips.is_empty() {
        eprintln!("Aucune adresse IP trouvée.");
        return;
    }

    let pb = ProgressBar::new(ips.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})"),
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

    // Extraction du motif unique du domaine cible
    let target_pattern = match get_target_pattern(domain, timeout_duration).await {
        Some(pattern) => pattern,
        None => {
            eprintln!("Impossible d'extraire un motif unique du domaine cible.");
            return;
        }
    };

    let semaphore = Arc::new(Semaphore::new(max_threads));

    let mut tasks = FuturesUnordered::new();

    for ip in ips {
        let ip = ip.trim().to_string();
        let domain = domain.to_string();
        let user_agents = user_agents.clone();
        let aggressive = aggressive;
        let timeout_duration = timeout_duration;
        let semaphore = semaphore.clone();
        let pb = pb.clone();
        let target_pattern = target_pattern.clone();

        let permit = semaphore.acquire_owned().await.unwrap();

        tasks.push(tokio::spawn(async move {
            let result = test_ip(
                ip,
                domain,
                user_agents,
                aggressive,
                timeout_duration,
                target_pattern,
            )
            .await;
            drop(permit);
            pb.inc(1);
            result
        }));
    }

    let mut possible_ips = Vec::new();

    while let Some(result) = tasks.next().await {
        if let Ok(Some(ip)) = result {
            possible_ips.push(ip);
        }
    }

    pb.finish_with_message("Scan terminé");

    if possible_ips.is_empty() {
        println!(
            "{}",
            format!("Aucune IP trouvée liée à {}", domain).red()
        );
    } else {
        println!("{}", "Adresses IP potentielles trouvées :".green());
        for ip in possible_ips {
            println!("{}", ip.green());
        }
    }
}

async fn test_ip(
    ip: String,
    domain: String,
    user_agents: Vec<String>,
    aggressive: bool,
    timeout_duration: Duration,
    target_pattern: String,
) -> Option<String> {
    let socket_addr: SocketAddr = match format!("{}:80", ip).parse() {
        Ok(addr) => addr,
        Err(_) => {
            eprintln!("Adresse IP invalide : {}", ip);
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
                            return Some(ip);
                        }
                    }
                }
            }
        }
    }
    None
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
        if let Ok(text) = resp.text().await {
            if let Some(title) = extract_title(&text) {
                return Some(title);
            }
        }
    }
    None
}

fn extract_title(html: &str) -> Option<String> {
    let document = Html::parse_document(html);
    let selector = Selector::parse("title").unwrap();

    document.select(&selector).next().map(|element| element.inner_html())
}

fn read_lines(filename: &str) -> Vec<String> {
    let file = File::open(filename).expect("Impossible d'ouvrir le fichier");
    let reader = BufReader::new(file);
    reader.lines().filter_map(Result::ok).collect()
}

fn parse_ip_range(ip_range: &str) -> Result<Vec<String>, String> {
    let parts: Vec<&str> = ip_range.split('-').collect();
    if parts.len() != 2 {
        return Err("Le format de la plage IP est invalide. Utilisez le format 'début-fin'.".to_string());
    }

    let start_ip = Ipv4Addr::from_str(parts[0]).map_err(|_| "Adresse IP de début invalide.".to_string())?;
    let end_ip = Ipv4Addr::from_str(parts[1]).map_err(|_| "Adresse IP de fin invalide.".to_string())?;

    let start: u32 = start_ip.into();
    let end: u32 = end_ip.into();

    if start > end {
        return Err("L'adresse IP de début est supérieure à l'adresse IP de fin.".to_string());
    }

    let max_ips = 1_000_000;
    let total_ips = end - start + 1;

    if total_ips > max_ips {
        return Err(format!(
            "La plage d'IP est trop grande ({} adresses). Veuillez spécifier une plage plus petite.",
            total_ips
        ));
    }

    let ips: Vec<String> = (start..=end)
        .map(|ip_num| Ipv4Addr::from(ip_num).to_string())
        .collect();

    Ok(ips)
}