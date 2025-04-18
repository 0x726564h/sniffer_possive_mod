# SNIffer

SNIffer is a command-line tool for detecting and analyzing SNI-based (Server Name Indication) network blocking and censorship. This tool helps identify different types of network filtering techniques including SNI-based blocking, DNS censorship, and TLS MITM (Man-in-the-Middle) attacks.

## Features

- **SNI Blocking Detection:** Identify when connections with SNI are blocked but work without SNI
- **DNS Censorship Detection:** Determine if domain names are being censored at the DNS level
- **TLS Certificate Analysis:** Detect suspicious certificates that might indicate MITM attacks
- **Parallel Processing:** Test multiple domains simultaneously for efficient scanning
- **Flexible Output Formats:** Choose between normal, verbose, JSON, or silent output
- **Timeout Configuration:** Set custom timeouts for network tests
- **Custom IP Testing:** Specify IP addresses directly to bypass DNS resolution

## Installation

### Using Cargo

```bash
cargo install sniffer
```

### Prerequisites

- Rust and Cargo (1.70.0 or newer)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/4383/sniffer.git
cd sniffer

# Build in release mode
cargo build --release

# The binary will be available at ./target/release/sniffer
```

## Usage

### Basic Usage

Test a single domain:
```bash
sniffer example.com
```

Test multiple domains:
```bash
sniffer facebook.com twitter.com youtube.com
```

### Advanced Options

```
USAGE:
    sniffer [OPTIONS] <DOMAINS>...

ARGS:
    <DOMAINS>...    One or more domains to check for SNI blocking

OPTIONS:
    -h, --help                 Print help information
    --ip <IP>                  IP address to use instead of resolving DNS
    --timeout <TIMEOUT>        Maximum timeout for each test in seconds [default: 10]
    --max-concurrency <MAX>    Maximum number of domains to test in parallel [default: 5]
    --output <FORMAT>          Output format: normal, json, verbose, or silent [default: normal]
    -V, --version              Print version information
```

### Examples

Basic check for SNI blocking:
```bash
sniffer facebook.com
```

Test multiple domains with limited concurrency:
```bash
sniffer tiktok.com youtube.com --max-concurrency 2
```

Test multiple domains from an input file:
```bash
cat domains.txt | xargs sniffer
```

Use a specific IP address (bypass DNS):
```bash
sniffer --ip 157.240.18.35 facebook.com
```

Set a shorter timeout and output as JSON:
```bash
sniffer --timeout 5 --output json censoredsite.com weibo.com
```

## Understanding Results

SNI Sniffer provides different types of results:

- **✅ OK**: No SNI blocking detected
- **⛔ BLOCKED (SNI)**: SNI blocking detected (connection works without SNI but fails with SNI)
- **⛔ BLOCKED (TOTAL)**: Complete blocking detected (no connection possible)
- **⛔ BLOCKED (DNS)**: DNS censorship detected (domain cannot be resolved)
- **⚠️ SUSPECTIOUS (MITM)**: Suspicious certificate detected (possible MITM attack)
- **❓ UNKNOWN**: Results are inconclusive

## How It Works

SNI Sniffer works by:

1. **DNS Resolution**: First resolving the domain name to an IP address
2. **Parallel Testing**: Performing two parallel TLS connection tests:
   - One with the correct SNI (Server Name Indication) field
   - One with a fake SNI value
3. **Certificate Analysis**: Analyzing the TLS certificate for validity and trustworthiness
4. **Analysis**: Comparing results to determine the type of blocking (if any)

If the connection with correct SNI fails but works with fake SNI, it indicates SNI-based blocking.

## Use Cases

- Detecting censorship in networks
- Verifying if websites are being blocked in certain regions
- Identifying MITM attacks in untrusted networks
- Troubleshooting TLS connectivity issues

## Limitations

- Does not detect all forms of censorship or blocking
- Might produce false positives in case of server misconfiguration
- Not designed to circumvent censorship, only to detect it

## License

[LGPL v2.1](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.