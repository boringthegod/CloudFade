# CloudFade

Unmask real IP address of a domain hidden behind Cloudflare by IPs bruteforcing.

## usage

```
Unmask real IP address of a domain hidden behind Cloudflare by IPs bruteforcing

USAGE:
    cloud_fade [FLAGS] [OPTIONS] <domain> <ipfile>

FLAGS:
        --aggressive    More intensive checks
    -h, --help          Prints help information
    -V, --version       Prints version information

OPTIONS:
        --iprange <IP_RANGE>      Specifies a range of IP addresses (for example, 51.15.0.0-51.15.10.255)
        --threads <NUMBER>        Set the maximum number of concurrent threads
        --timeout <SECONDS>       Waiting time for each request in seconds [default: 5]
        --useragents <UA_FILE>    File containing the list of user agents

ARGS:
    <domain>    Domain to unmask
    <ipfile>    File containing list of IP addresses

Examples:
  ./cloud_fade predictasearch.com ipsfile.txt
  ./cloud_fade predictasearch.com --iprange 167.99.32.0-167.99.32.255
  ./cloud_fade predictasearch.com --iprange 167.99.32.0-167.99.32.255 --threads 10 --timeout 8 --useragents useragents.txt --aggressive
```

## prerequisites

- [Rust](https://www.rust-lang.org/tools/install)

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