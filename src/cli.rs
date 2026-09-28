//! Command-line parsing and runtime configuration for proxlet.
//!
//! This module owns the public CLI surface and converts parsed flags into the
//! normalized configuration consumed by the proxy server.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Result, bail};
use clap::{Parser, ValueEnum};
use ipnet::IpNet;
use url::Url;

const DEFAULT_MAX_FRAME_SIZE_KIB: usize = 16;
const MAX_FRAME_SIZE_VALUES_KIB: [usize; 4] = [8, 16, 32, 64];

/// Start a portable proxy server with optional upstream proxy chaining.
#[derive(Clone, Debug, Parser)]
#[command(name = "proxlet", version, about)]
pub struct Cli {
    /// Start proxlet in the background without using the current terminal streams.
    #[arg(short = 'd', long)]
    pub daemon: bool,

    /// Permit client IPs specified as addresses, comma-separated addresses, or CIDR networks.
    #[arg(
        long = "allow-ip",
        value_name = "allow-src-ip",
        num_args = 1..,
        value_delimiter = ','
    )]
    pub allow_ip: Vec<AllowedIp>,

    /// Host address on which to listen.
    #[arg(short = 'l', long = "lhost", default_value = "127.0.0.1")]
    pub lhost: String,

    /// Port on which to listen.
    #[arg(short = 'p', long = "lport", default_value_t = 1080)]
    pub lport: u16,

    /// Password. Authentication is enabled only when both --user and --auth are set.
    #[arg(short = 'a', long = "auth", value_name = "password")]
    pub password: Option<String>,

    /// Username. Authentication is enabled only when both --user and --auth are set.
    #[arg(short = 'u', long = "user", value_name = "username")]
    pub username: Option<String>,

    /// Proxy protocol accepted by the listening socket.
    #[arg(short = 't', long = "type", default_value_t = ProxyType::Http)]
    pub proxy_type: ProxyType,

    /// Chain traffic through an upstream proxy URL.
    #[arg(
        long,
        value_name = "SCHEMA_URL",
        help = "Chain traffic through an upstream proxy URL. Examples: http://user:pass@host:8080, https://user:pass@host:8443, socks5://user:pass@host:1080, fakehttp://secret@host:8080, ssh://user:pass@host:22, ssh://user@host:22?key=/path/to/id_rsa"
    )]
    pub proxy: Option<Url>,

    /// AES secret for fakehttp listener encryption.
    #[arg(long, value_name = "SECRET")]
    pub aes_secret: Option<String>,

    /// Maximum fakehttp encrypted frame payload size in KiB. Allowed values: 8, 16, 32, 64.
    #[arg(
        long,
        value_name = "KB",
        default_value_t = DEFAULT_MAX_FRAME_SIZE_KIB,
        value_parser = parse_max_frame_size
    )]
    pub max_frame_size: usize,

    /// DNS, TCP dial, and handshake timeout in seconds. Established tunnels are not idle-timed out.
    #[arg(
        long,
        value_name = "SECS",
        default_value_t = DEFAULT_CONNECT_TIMEOUT_SECS,
        value_parser = parse_connect_timeout
    )]
    pub connect_timeout: u64,

    /// PEM CA certificate bundle used to verify an HTTPS upstream proxy.
    #[arg(long, value_name = "FILE", requires = "proxy")]
    pub proxy_ca: Option<PathBuf>,

    /// PEM certificate chain for HTTPS listener mode.
    #[arg(long, value_name = "FILE", requires = "tls_key")]
    pub tls_cert: Option<PathBuf>,

    /// PEM private key for HTTPS listener mode.
    #[arg(long, value_name = "FILE", requires = "tls_cert")]
    pub tls_key: Option<PathBuf>,

    /// Append daemon stdout to this file. Requires --daemon.
    #[arg(long, value_name = "FILE", requires = "daemon")]
    pub log_file: Option<PathBuf>,

    /// Write the background process id after the listener is bound. Requires --daemon.
    #[arg(long, value_name = "FILE", requires = "daemon")]
    pub pid_file: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
/// Proxy protocols supported by the listening socket.
pub enum ProxyType {
    /// HTTP forward proxy mode.
    Http,
    /// HTTPS listener mode that wraps HTTP proxy traffic in TLS.
    Https,
    /// SOCKS5 mode with local DNS resolution.
    Socks5,
    /// SOCKS5 mode with remote DNS resolution when used as an upstream.
    Socks5h,
    /// Protocol auto-detection mode for HTTP, HTTPS, and SOCKS5.
    Mixed,
    /// HTTP-shaped tunnel mode for proxlet-to-proxlet links.
    #[value(name = "fakehttp")]
    FakeHttp,
}

impl std::fmt::Display for ProxyType {
    /// Format the proxy type as its command-line value.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatter provided by the formatting machinery.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` when the proxy type is written successfully.
    ///
    /// # Errors
    ///
    /// Returns the formatter error if writing to `formatter` fails.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Socks5 => "socks5",
            Self::Socks5h => "socks5h",
            Self::Mixed => "mixed",
            Self::FakeHttp => "fakehttp",
        })
    }
}

/// Parse the fakehttp maximum frame size from KiB CLI input.
///
/// # Parameters
///
/// * `value` - User-provided frame size in KiB.
///
/// # Returns
///
/// Returns the accepted frame size in KiB.
///
/// # Errors
///
/// Returns an error string when the input is not numeric or not one of the
/// supported values: 8, 16, 32, or 64.
fn parse_max_frame_size(value: &str) -> std::result::Result<usize, String> {
    let size = value
        .parse::<usize>()
        .map_err(|_| format!("invalid max frame size: {value}"))?;
    if MAX_FRAME_SIZE_VALUES_KIB.contains(&size) {
        Ok(size)
    } else {
        Err("max frame size must be one of 8, 16, 32, or 64".to_owned())
    }
}

const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Parse a positive connect timeout in seconds.
///
/// # Parameters
///
/// * `value` - Raw CLI value.
///
/// # Returns
///
/// Returns the accepted timeout in seconds.
///
/// # Errors
///
/// Returns an error string when the input is not a positive integer.
fn parse_connect_timeout(value: &str) -> std::result::Result<u64, String> {
    let seconds = value
        .parse::<u64>()
        .map_err(|_| format!("invalid connect timeout: {value}"))?;
    if seconds == 0 {
        Err("connect timeout must be greater than zero".to_owned())
    } else {
        Ok(seconds)
    }
}

#[derive(Clone, Debug)]
/// A client IP allow-list entry.
pub enum AllowedIp {
    /// A single allowed IP address.
    Address(IpAddr),
    /// An allowed CIDR network.
    Network(IpNet),
}

impl AllowedIp {
    /// Check whether an IP address is accepted by this allow-list entry.
    ///
    /// # Parameters
    ///
    /// * `ip` - Client IP address to test.
    ///
    /// # Returns
    ///
    /// Returns `true` when `ip` matches the address or belongs to the network.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match self {
            Self::Address(allowed) => allowed == ip,
            Self::Network(network) => network.contains(ip),
        }
    }
}

impl FromStr for AllowedIp {
    type Err = anyhow::Error;

    /// Parse an IP address or CIDR network allow-list entry.
    ///
    /// # Parameters
    ///
    /// * `value` - Text value supplied on the command line.
    ///
    /// # Returns
    ///
    /// Returns an [`AllowedIp`] address or network entry.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is neither an IP address nor a CIDR
    /// network.
    fn from_str(value: &str) -> Result<Self> {
        if let Ok(ip) = value.parse() {
            return Ok(Self::Address(ip));
        }
        if let Ok(network) = value.parse() {
            return Ok(Self::Network(network));
        }
        bail!("invalid IP address or CIDR network: {value}")
    }
}

#[derive(Clone, Debug)]
/// Username/password credentials used by listener authentication.
pub struct Auth {
    /// Expected username.
    pub username: String,
    /// Expected password.
    pub password: String,
}

#[derive(Clone, Debug)]
/// Normalized runtime configuration used by the server.
pub struct Config {
    /// Resolved listen socket address.
    pub listen: SocketAddr,
    /// Optional client IP allow-list.
    pub allowed_ips: Vec<AllowedIp>,
    /// Optional listener authentication credentials.
    pub auth: Option<Auth>,
    /// Listener proxy protocol.
    pub proxy_type: ProxyType,
    /// Optional upstream proxy URL.
    pub upstream: Option<Url>,
    /// Optional fakehttp AES encryption secret.
    pub aes_secret: Option<String>,
    /// fakehttp maximum frame payload size in bytes.
    pub max_frame_size: usize,
    /// Optional CA bundle for HTTPS upstream verification.
    pub upstream_ca: Option<PathBuf>,
    /// Optional TLS certificate chain for HTTPS listener mode.
    pub tls_cert: Option<PathBuf>,
    /// Optional TLS private key for HTTPS listener mode.
    pub tls_key: Option<PathBuf>,
    /// DNS, TCP dial, and handshake deadline. Established tunnels are not affected.
    pub connect_timeout: Duration,
}

impl Cli {
    /// Convert parsed CLI flags into a normalized runtime configuration.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed command-line options.
    ///
    /// # Returns
    ///
    /// Returns a [`Config`] with resolved listen address and byte-based frame
    /// sizing.
    ///
    /// # Errors
    ///
    /// Returns an error when HTTPS listener TLS files are incomplete, the listen
    /// host cannot be resolved, or address resolution fails.
    pub async fn into_config(self) -> Result<Config> {
        if self.proxy_type == ProxyType::Https && self.tls_cert.is_none() {
            bail!("--type https requires --tls-cert and --tls-key")
        }
        let listen = tokio::net::lookup_host((self.lhost.as_str(), self.lport))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("could not resolve listen host {}", self.lhost))?;
        let auth = match (self.username, self.password) {
            (Some(username), Some(password)) => Some(Auth { username, password }),
            _ => None,
        };
        Ok(Config {
            listen,
            allowed_ips: self.allow_ip,
            auth,
            proxy_type: self.proxy_type,
            upstream: self.proxy,
            aes_secret: self.aes_secret,
            max_frame_size: self.max_frame_size * 1024,
            upstream_ca: self.proxy_ca,
            tls_cert: self.tls_cert,
            tls_key: self.tls_key,
            connect_timeout: Duration::from_secs(self.connect_timeout),
        })
    }
}
