//! Command-line parsing and runtime configuration for proxlet.
//!
//! This module owns the public CLI surface and converts parsed flags into the
//! normalized configuration consumed by the proxy server.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

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

    /// Maximum fakehttp encrypted frame payload size in KiB.
    #[arg(
        long,
        value_name = "KB",
        default_value_t = DEFAULT_MAX_FRAME_SIZE_KIB,
        value_parser = parse_max_frame_size
    )]
    pub max_frame_size: usize,

    /// PEM CA certificate bundle used to verify an HTTPS upstream proxy.
    #[arg(long, value_name = "FILE", requires = "proxy")]
    pub proxy_ca: Option<PathBuf>,

    /// PEM certificate chain for HTTPS listener mode.
    #[arg(long, value_name = "FILE", requires = "tls_key")]
    pub tls_cert: Option<PathBuf>,

    /// PEM private key for HTTPS listener mode.
    #[arg(long, value_name = "FILE", requires = "tls_cert")]
    pub tls_key: Option<PathBuf>,
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn parses_requested_command_line_options() {
        let cli = Cli::try_parse_from([
            "proxlet",
            "-l",
            "0.0.0.0",
            "--daemon",
            "-p",
            "3128",
            "-t",
            "mixed",
            "--allow-ip",
            "127.0.0.1,127.0.0.2",
            "127.0.0.1/8",
            "--proxy",
            "socks5h://user:pass@127.0.0.1:1080",
            "--aes-secret",
            "fake-secret",
            "--max-frame-size",
            "32",
            "--proxy-ca",
            "certs/proxlet-ca.pem",
        ])
        .expect("valid command line");

        assert_eq!(cli.lport, 3128);
        assert!(cli.daemon);
        assert_eq!(cli.proxy_type, ProxyType::Mixed);
        assert_eq!(cli.allow_ip.len(), 3);
        assert!(
            cli.allow_ip
                .iter()
                .any(|allowed| allowed.contains(&"127.0.0.2".parse().expect("IP")))
        );
        assert_eq!(cli.proxy.expect("upstream").scheme(), "socks5h");
        assert_eq!(cli.aes_secret.as_deref(), Some("fake-secret"));
        assert_eq!(cli.max_frame_size, 32);
        assert_eq!(
            cli.proxy_ca.expect("proxy CA"),
            PathBuf::from("certs/proxlet-ca.pem")
        );
    }

    #[test]
    fn parses_each_allow_ip_input_form() {
        let single =
            Cli::try_parse_from(["proxlet", "--allow-ip", "127.0.0.1"]).expect("single address");
        let comma_separated = Cli::try_parse_from(["proxlet", "--allow-ip", "127.0.0.1,127.0.0.2"])
            .expect("comma-separated addresses");
        let cidr =
            Cli::try_parse_from(["proxlet", "--allow-ip", "127.0.0.1/8"]).expect("CIDR network");

        assert_eq!(single.allow_ip.len(), 1);
        assert_eq!(comma_separated.allow_ip.len(), 2);
        assert_eq!(cidr.allow_ip.len(), 1);
        assert!(cidr.allow_ip[0].contains(&"127.10.20.30".parse().expect("IP")));
    }

    #[test]
    fn parses_fakehttp_proxy_type() {
        let cli = Cli::try_parse_from(["proxlet", "-t", "fakehttp"]).expect("fakehttp type");

        assert_eq!(cli.proxy_type, ProxyType::FakeHttp);
    }

    #[test]
    fn validates_max_frame_size_values() {
        let cli = Cli::try_parse_from(["proxlet", "--max-frame-size", "64"])
            .expect("valid max frame size");

        assert_eq!(cli.max_frame_size, 64);
        assert!(Cli::try_parse_from(["proxlet", "--max-frame-size", "12"]).is_err());
    }

    #[test]
    fn proxy_help_includes_uri_examples() {
        let mut help = Vec::new();
        Cli::command().write_help(&mut help).expect("help renders");
        let help = String::from_utf8(help).expect("help is UTF-8");

        assert!(help.contains("http://user:pass@host:8080"));
        assert!(help.contains("https://user:pass@host:8443"));
        assert!(help.contains("socks5://user:pass@host:1080"));
        assert!(help.contains("fakehttp://secret@host:8080"));
        assert!(help.contains("ssh://user:pass@host:22"));
        assert!(help.contains("ssh://user@host:22?key=/path/to/id_rsa"));
    }
}
