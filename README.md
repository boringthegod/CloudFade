# CloudFade

Unmask real IP address of a domain hidden behind Cloudflare by IPs bruteforcing.

*You can limit the range of IPs to be tested by first using [censhess](https://github.com/boringthegod/censhess)*

## usage

```
Unmask real IP address of a domain hidden behind Cloudflare by IPs bruteforcing

USAGE:
    cloud_fade [FLAGS] [OPTIONS] --domain <domain> --targetsfile <TARGETS_FILE> <--ipfile <ipfile>|--iprange <IP_RANGE>|--asn <ASN_CODE>>

FLAGS:
        --aggressive    More intensive checks
    -h, --help          Prints help information
    -V, --version       Prints version information

OPTIONS:
        --asn <ASN_CODE>                Specify an ASN code (e.g., AS714) to scan all ranges associated with it
    -d, --domain <domain>               Domain to unmask
    -i, --ipfile <ipfile>               File containing list of IP addresses
        --iprange <IP_RANGE>            Specifies a single IP address, a range of IP addresses (e.g., 51.15.0.0-
                                        51.15.10.255), or a CIDR notation (e.g., 51.15.0.0/16)
        --output <OUTPUT_FILE>          File to write the results
    -t, --targetsfile <TARGETS_FILE>    File containing list of domains
        --threads <NUMBER>              Set the maximum number of concurrent threads
        --timeout <SECONDS>             Waiting time for each request in seconds [default: 5]
        --useragents <UA_FILE>          File containing the list of user agents

Examples:
  ./cloud_fade --domain predictasearch.com --iprange 167.99.32.0/24
  ./cloud_fade --domain predictasearch.com --asn AS14061
  ./cloud_fade --domain predictasearch.com --ipfile ipsfile.txt
  ./cloud_fade --targetsfile targets.txt --ipfile ipsfile.txt
  ./cloud_fade --domain predictasearch.com --iprange 167.99.32.0-167.99.32.255
  ./cloud_fade --domain predictasearch.com --iprange 167.99.32.0-167.99.32.255 --threads 10 --timeout 8 --useragents useragents.txt --aggressive
```

## prerequisites

- [Rust](https://www.rust-lang.org/tools/install)
- whois
- cmake for linux users : `sudo apt install cmake`

## installation

```
cargo install cloud_fade
```

## compile

Linux:
```
cargo build --release
```

Windows: 

```
sudo apt update && sudo apt install mingw-w64
rustup target add x86_64-pc-windows-gnu
rustup toolchain install stable-x86_64-pc-windows-gnu
```

```
cargo build --release --target x86_64-pc-windows-gnu
```

## credits

- [HuGe](https://x.com/realdumbledork)
