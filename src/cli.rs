use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Result, bail};
use clap::{Parser, ValueEnum};
use ipnet::IpNet;
use url::Url;

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
pub enum ProxyType {
    Http,
    Https,
    Socks5,
    Socks5h,
    Mixed,
    #[value(name = "fakehttp")]
    FakeHttp,
}

impl std::fmt::Display for ProxyType {
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

#[derive(Clone, Debug)]
pub enum AllowedIp {
    Address(IpAddr),
    Network(IpNet),
}

impl AllowedIp {
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match self {
            Self::Address(allowed) => allowed == ip,
            Self::Network(network) => network.contains(ip),
        }
    }
}

impl FromStr for AllowedIp {
    type Err = anyhow::Error;

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
pub struct Auth {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub allowed_ips: Vec<AllowedIp>,
    pub auth: Option<Auth>,
    pub proxy_type: ProxyType,
    pub upstream: Option<Url>,
    pub aes_secret: Option<String>,
    pub upstream_ca: Option<PathBuf>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
}

impl Cli {
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
