use anyhow::Result;
use clap::{Parser, ValueEnum};
use colored::Colorize;
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use rustls::{ClientConfig, RootCertStore};
use std::convert::TryFrom;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use x509_parser;
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Parser, Debug)]
#[command(author, version, about = "SNI blocking detection tool", long_about = None)]
struct Cli {
    /// Domains to check
    #[arg(required = true)]
    domains: Vec<String>,

    /// IP address to use instead of resolving DNS
    #[arg(long)]
    ip: Option<IpAddr>,

    /// Maximum timeout for each test in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Maximum number of domains to test in parallel
    #[arg(long, default_value_t = 5)]
    max_concurrency: usize,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Normal)]
    output: OutputFormat,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Normal,
    Json,
    Verbose,
    Silent,
}

#[derive(Debug, Serialize, Deserialize)]
enum BlockageType {
    SniBlockageProbable,
    NoBlockage,
    TotalBlockage,
    DnsCensored,
    SuspectCertificate,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
struct TestResult {
    domain: String,
    ip: Option<IpAddr>,
    with_sni_success: bool,
    without_sni_success: bool,
    with_sni_error: Option<String>,
    without_sni_error: Option<String>,
    dns_resolution_success: bool,
    certificate_status: Option<String>,
    conclusion: BlockageType,
    details: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the logger
    tracing_subscriber::fmt::init();
    
    // Parse CLI arguments
    let cli = Cli::parse();
    
    // Create a collection for futures
    let mut domain_futures = FuturesUnordered::new();
    
    // Add each domain to process
    for domain in cli.domains.clone() {
        domain_futures.push(process_domain(
            domain, 
            cli.ip, 
            Duration::from_secs(cli.timeout)
        ));
    }
    
    // Initialize progress bar only when multiple domains are being analyzed
    let pb = if cli.domains.len() > 1 && cli.output != OutputFormat::Silent && cli.output != OutputFormat::Json {
        let pb = ProgressBar::new(cli.domains.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) Domain: {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("#>-")
        );
        Some(pb)
    } else {
        None
    };
    
    // Limit concurrency if needed
    let mut results = Vec::new();
    while let Some(result) = domain_futures.next().await {
        let result = result?;
        
        // Update progress bar if it exists
        if let Some(pb) = &pb {
            pb.set_message(result.domain.clone());
            pb.inc(1);
        }
        
        results.push(result);
        
        // Optional: add logic to limit concurrency
        if domain_futures.len() > cli.max_concurrency {
            // Wait for at least one domain to be processed before adding more
        }
    }
    
    // Finish progress bar if it exists
    if let Some(pb) = pb {
        pb.finish_with_message("Processing complete");
    }
    
    // Display results according to the requested format
    output_results(&results, cli.output)?;
    
    Ok(())
}

async fn process_domain(domain: String, ip: Option<IpAddr>, timeout_duration: Duration) -> Result<TestResult> {
    // Resolve IP if necessary
    let target_ip = match ip {
        Some(ip) => {
            // Use the provided IP
            Some(ip)
        },
        None => {
            // Resolve DNS
            resolve_dns(&domain).await
        }
    };
    
    // Prepare the result
    let mut result = TestResult {
        domain: domain.clone(),
        ip: target_ip,
        with_sni_success: false,
        without_sni_success: false,
        with_sni_error: None,
        without_sni_error: None,
        dns_resolution_success: target_ip.is_some(),
        certificate_status: None,
        conclusion: BlockageType::Unknown,
        details: String::new(),
    };
    
    // If no IP, unable to continue tests
    if target_ip.is_none() {
        result.conclusion = BlockageType::DnsCensored;
        result.details = format!("DNS resolution failed for {}", domain);
        return Ok(result);
    }
    
    // Run tests with and without SNI in parallel
    let target_ip = target_ip.unwrap();
    
    let (with_sni_result, without_sni_result) = tokio::join!(
        timeout(
            timeout_duration,
            test_with_sni(domain.clone(), target_ip)
        ),
        timeout(
            timeout_duration,
            test_without_sni(domain.clone(), target_ip)
        )
    );
    
    // Process results of tests with SNI
    match with_sni_result {
        Ok(Ok(cert_info)) => {
            result.with_sni_success = true;
            result.certificate_status = Some(verify_certificate(&domain, &cert_info));
            
            // Check if the certificate is suspicious
            if let Some(status) = &result.certificate_status {
                if status.contains("suspicious") {
                    result.conclusion = BlockageType::SuspectCertificate;
                }
            }
        },
        Ok(Err(e)) => {
            result.with_sni_success = false;
            result.with_sni_error = Some(e.to_string());
        },
        Err(_) => {
            result.with_sni_success = false;
            result.with_sni_error = Some("Timeout".to_string());
        }
    }
    
    // Process results of tests without SNI
    match without_sni_result {
        Ok(Ok(_)) => {
            result.without_sni_success = true;
        },
        Ok(Err(e)) => {
            result.without_sni_success = false;
            result.without_sni_error = Some(e.to_string());
        },
        Err(_) => {
            result.without_sni_success = false;
            result.without_sni_error = Some("Timeout".to_string());
        }
    }
    
    // Determine conclusion based on results
    result.conclusion = determine_blockage_type(&result);
    result.details = get_details(&result);
    
    Ok(result)
}

/// Resolves a domain name to an IP address
async fn resolve_dns(domain: &str) -> Option<IpAddr> {
    // Create resolver - this function returns the resolver directly, not a Result
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );
    
    // Lookup the IP
    match resolver.lookup_ip(domain).await {
        Ok(response) => response.iter().next(),
        Err(_) => None
    }
}

/// Performs a connection test with SNI
async fn test_with_sni(domain: String, ip: IpAddr) -> Result<String> {
    // Configure TLS client with SNI
    let mut root_store = RootCertStore::empty();
    
    // Add Mozilla's trusted root certificates
    root_store.add_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        })
    );
    
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    let connector = TlsConnector::from(Arc::new(config));
    
    // Convert domain name to rustls::ServerName for SNI
    let dns_name = rustls::ServerName::try_from(domain.as_str())
        .map_err(|_| anyhow::anyhow!("Invalid DNS name"))?;
    
    // TCP connection
    let socket = TcpStream::connect((ip, 443)).await?;
    
    // TLS connection with SNI
    let mut tls_stream = connector.connect(dns_name, socket).await?;
    
    // Send a basic HTTP request to get a response
    tls_stream.write_all(b"GET / HTTP/1.1\r\nHost: ").await?;
    tls_stream.write_all(domain.as_bytes()).await?;
    tls_stream.write_all(b"\r\nConnection: close\r\n\r\n").await?;
    
    // Read the beginning of the response
    let mut buffer = vec![0; 1024];
    let _n = tls_stream.read(&mut buffer).await?;
    
    // Get certificate information
    let server_cert = match tls_stream.get_ref().1.peer_certificates() {
        Some(certs) if !certs.is_empty() => {
            // Found certificates
            &certs[0].0
        },
        _ => {
            return Err(anyhow::anyhow!("No server certificate received"));
        }
    };
    
    // Extract certificate information using x509-parser
    extract_cert_info(server_cert, &domain)
}

/// Performs a connection test without SNI (or with a fake SNI)
async fn test_without_sni(domain: String, ip: IpAddr) -> Result<String> {
    // Configure TLS client, but with a fake or absent SNI
    let mut root_store = RootCertStore::empty();
    
    // Add Mozilla's trusted root certificates
    root_store.add_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        })
    );
    
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    let connector = TlsConnector::from(Arc::new(config));
    
    // Use a fictitious domain name for SNI
    let dns_name = rustls::ServerName::try_from("example-fictitious-domain-for-testing.com")
        .map_err(|_| anyhow::anyhow!("Invalid DNS name"))?;
    
    // TCP connection
    let socket = TcpStream::connect((ip, 443)).await?;
    
    // TLS connection with fake SNI
    let mut tls_stream = connector.connect(dns_name, socket).await?;
    
    // Send a basic HTTP request
    tls_stream.write_all(b"GET / HTTP/1.1\r\nHost: ").await?;
    tls_stream.write_all(domain.as_bytes()).await?;
    tls_stream.write_all(b"\r\nConnection: close\r\n\r\n").await?;
    
    // Read the beginning of the response
    let mut buffer = vec![0; 1024];
    let _n = tls_stream.read(&mut buffer).await?;
    
    // If we get here, it means the connection succeeded despite an incorrect SNI
    Ok("Connection succeeded despite incorrect SNI".to_string())
}

/// Extract certificate information using x509-parser
fn extract_cert_info(cert_data: &[u8], _domain: &str) -> Result<String> {
    match x509_parser::parse_x509_certificate(cert_data) {
        Ok((_, cert)) => {
            // Extract certificate information
            let subject = cert.subject().to_string();
            let issuer = cert.issuer().to_string();
            
            // Convert ASN1Time to String safely
            let not_before = match cert.validity().not_before.to_rfc2822() {
                Ok(time_str) => time_str,
                Err(_) => "Invalid date".to_string(),
            };
            
            let not_after = match cert.validity().not_after.to_rfc2822() {
                Ok(time_str) => time_str,
                Err(_) => "Invalid date".to_string(),
            };
            
            Ok(format!(
                "Subject: {}, Issuer: {}, Valid from: {} to: {}",
                subject, issuer, not_before, not_after
            ))
        },
        Err(e) => Err(anyhow::anyhow!("Certificate parsing error: {}", e))
    }
}

/// Verifies certificate validity
fn verify_certificate(domain: &str, cert_info: &str) -> String {
    // Check if the certificate contains the domain name
    if !cert_info.contains(domain) && !cert_info.contains(&format!("*.{}", domain.split('.').skip(1).collect::<Vec<_>>().join("."))) {
        return format!("Suspicious certificate: does not contain domain name {}", domain);
    }
    
    // Check if the certificate is issued by a recognized certificate authority
    if cert_info.contains("Let's Encrypt") || 
       cert_info.contains("DigiCert") || 
       cert_info.contains("Comodo") || 
       cert_info.contains("GlobalSign") ||
       cert_info.contains("GeoTrust") ||
       cert_info.contains("Amazon") ||
       cert_info.contains("Google Trust Services") {
        return format!("Valid certificate for {}", domain);
    }
    
    // If the issuer is not recognized, mark as suspicious
    format!("Suspicious certificate: unrecognized issuer for {}", domain)
}

/// Determines the type of blocking based on test results
fn determine_blockage_type(result: &TestResult) -> BlockageType {
    if !result.dns_resolution_success {
        return BlockageType::DnsCensored;
    }
    
    if let Some(status) = &result.certificate_status {
        if status.contains("suspicious") {
            return BlockageType::SuspectCertificate;
        }
    }
    
    match (result.with_sni_success, result.without_sni_success) {
        (false, true) => BlockageType::SniBlockageProbable,
        (true, false) => BlockageType::NoBlockage, // Normal behavior
        (false, false) => BlockageType::TotalBlockage,
        (true, true) => {
            // Both connections succeed, which is unusual
            // Could indicate a proxy that lets everything pass
            BlockageType::NoBlockage
        }
    }
}

/// Generates a detailed description of the results
fn get_details(result: &TestResult) -> String {
    match result.conclusion {
        BlockageType::SniBlockageProbable => {
            format!("Probable SNI blocking on {}. Connection with SNI fails but works without SNI.", result.domain)
        },
        BlockageType::NoBlockage => {
            format!("No SNI blocking detected for {}.", result.domain)
        },
        BlockageType::TotalBlockage => {
            format!("Total blocking for {}. Connections with and without SNI fail.", result.domain)
        },
        BlockageType::DnsCensored => {
            format!("DNS censorship detected for {}. Unable to resolve domain name.", result.domain)
        },
        BlockageType::SuspectCertificate => {
            format!("Suspicious certificate for {}. Possible MITM or TLS proxy.", result.domain)
        },
        BlockageType::Unknown => {
            format!("Indeterminate result for {}.", result.domain)
        }
    }
}

/// Displays results according to the requested format
fn output_results(results: &[TestResult], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => {
            // JSON output
            println!("{}", serde_json::to_string_pretty(results)?);
        },
        OutputFormat::Silent => {
            // Don't display anything, just the return code
        },
        OutputFormat::Verbose => {
            // Detailed output
            for result in results {
                println!("{}", "=".repeat(50));
                println!("Domain: {}", result.domain.bold());
                if let Some(ip) = result.ip {
                    println!("IP: {}", ip);
                } else {
                    println!("IP: {}", "Not resolved".red());
                }
                
                println!("\nTest with SNI: {}", if result.with_sni_success { "Success".green() } else { "Failed".red() });
                if let Some(err) = &result.with_sni_error {
                    println!("  Error: {}", err);
                }
                
                println!("Test without SNI: {}", if result.without_sni_success { "Success".yellow() } else { "Failed".blue() });
                if let Some(err) = &result.without_sni_error {
                    println!("  Error: {}", err);
                }
                
                if let Some(cert) = &result.certificate_status {
                    println!("Certificate: {}", cert);
                }
                
                println!("\nConclusion: {}", match result.conclusion {
                    BlockageType::SniBlockageProbable => "SNI blocking probable".red(),
                    BlockageType::NoBlockage => "No blocking".green(),
                    BlockageType::TotalBlockage => "Total blocking".red(),
                    BlockageType::DnsCensored => "DNS censored".red(),
                    BlockageType::SuspectCertificate => "Suspicious certificate (MITM)".yellow(),
                    BlockageType::Unknown => "Indeterminate".yellow(),
                });
                
                println!("Details: {}", result.details);
            }
        },
        OutputFormat::Normal => {
            // Normal output, less verbose
            for result in results {
                let status = match result.conclusion {
                    BlockageType::SniBlockageProbable => "⛔ BLOCKED (SNI)".red(),
                    BlockageType::NoBlockage => "✅ OK".green(),
                    BlockageType::TotalBlockage => "⛔ BLOCKED (TOTAL)".red(),
                    BlockageType::DnsCensored => "⛔ BLOCKED (DNS)".red(),
                    BlockageType::SuspectCertificate => "⚠️ SUSPICIOUS (MITM)".yellow(),
                    BlockageType::Unknown => "❓ UNKNOWN".yellow(),
                };
                
                println!("{:30} {}", result.domain.bold(), status);
            }
        }
    }
    
    Ok(())
}
