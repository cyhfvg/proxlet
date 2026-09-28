//! Command-line parsing and runtime configuration for proxlet.
//!
//! This module owns the public CLI surface and converts parsed flags into the
//! normalized configuration consumed by the proxy server.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
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

    /// Password. Requires --user. Mutually exclusive with --auth-file and PROXLET_AUTH.
    #[arg(
        short = 'a',
        long = "auth",
        value_name = "password",
        requires = "username",
        conflicts_with = "auth_file"
    )]
    pub password: Option<String>,

    /// Password file, mode 0600. Requires --user. Mutually exclusive with --auth and PROXLET_AUTH.
    #[arg(
        long = "auth-file",
        value_name = "FILE",
        requires = "username",
        conflicts_with = "password"
    )]
    pub auth_file: Option<PathBuf>,

    /// Username. Requires --auth, --auth-file, or PROXLET_AUTH.
    #[arg(short = 'u', long = "user", value_name = "username")]
    pub username: Option<String>,

    /// Proxy protocol accepted by the listening socket.
    #[arg(short = 't', long = "type", default_value_t = ProxyType::Http)]
    pub proxy_type: ProxyType,

    /// Chain traffic through an upstream proxy URL.
    #[arg(
        long,
        value_name = "SCHEMA_URL",
        conflicts_with = "proxy_file",
        help = "Chain traffic through an upstream proxy URL. Examples: http://user:pass@host:8080, https://user:pass@host:8443, socks5://user:pass@host:1080, fakehttp://secret@host:8080, ssh://user:pass@host:22, ssh://user@host:22?key=/path/to/id_rsa. Prefer --proxy-file when the URL contains a secret."
    )]
    pub proxy: Option<Url>,

    /// Upstream proxy URL file, mode 0600. Mutually exclusive with --proxy and PROXLET_PROXY.
    #[arg(long = "proxy-file", value_name = "FILE", conflicts_with = "proxy")]
    pub proxy_file: Option<PathBuf>,

    /// AES secret for fakehttp listener encryption.
    #[arg(long, value_name = "SECRET", conflicts_with = "aes_secret_file")]
    pub aes_secret: Option<String>,

    /// AES secret file, mode 0600. Mutually exclusive with --aes-secret and PROXLET_AES_SECRET.
    #[arg(
        long = "aes-secret-file",
        value_name = "FILE",
        conflicts_with = "aes_secret"
    )]
    pub aes_secret_file: Option<PathBuf>,

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
    #[arg(long, value_name = "FILE")]
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
    /// Returns an error when only one of --user and a password source is set,
    /// secret sources conflict, a secret file is unsafe, HTTPS listener TLS
    /// files are incomplete, the listen host cannot be resolved, or address
    /// resolution fails.
    pub async fn into_config(self) -> Result<Config> {
        if self.proxy_type == ProxyType::Https && self.tls_cert.is_none() {
            bail!("--type https requires --tls-cert and --tls-key")
        }
        self.require_upstream_for_ca()?;
        let password = self.resolved_password()?;
        let aes_secret = self.resolved_aes_secret()?;
        let upstream = self.resolved_upstream()?;
        let auth = match (self.username, password) {
            (Some(username), Some(password)) => Some(Auth { username, password }),
            (None, None) => None,
            (Some(_), None) => bail!("--user requires --auth"),
            (None, Some(_)) => bail!("--auth requires --user"),
        };
        let listen = tokio::net::lookup_host((self.lhost.as_str(), self.lport))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("could not resolve listen host {}", self.lhost))?;
        Ok(Config {
            listen,
            allowed_ips: self.allow_ip,
            auth,
            proxy_type: self.proxy_type,
            upstream,
            aes_secret,
            max_frame_size: self.max_frame_size * 1024,
            upstream_ca: self.proxy_ca,
            tls_cert: self.tls_cert,
            tls_key: self.tls_key,
            connect_timeout: Duration::from_secs(self.connect_timeout),
        })
    }

    /// Resolve the listener password from the flag, file, or environment.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed command-line options.
    ///
    /// # Returns
    ///
    /// Returns the password, or `None` when authentication is not configured.
    ///
    /// # Errors
    ///
    /// Returns an error when more than one password source is set or the file
    /// is unsafe.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let password = cli.resolved_password()?;
    /// ```
    pub(crate) fn resolved_password(&self) -> Result<Option<String>> {
        crate::secret::resolve(
            self.password.clone(),
            self.auth_file.as_deref(),
            "--auth",
            "--auth-file",
            "PROXLET_AUTH",
        )
    }

    /// Resolve the fakehttp AES secret from the flag, file, or environment.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed command-line options.
    ///
    /// # Returns
    ///
    /// Returns the secret, or `None` when fakehttp encryption is not configured.
    ///
    /// # Errors
    ///
    /// Returns an error when more than one secret source is set or the file is
    /// unsafe.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let secret = cli.resolved_aes_secret()?;
    /// ```
    pub(crate) fn resolved_aes_secret(&self) -> Result<Option<String>> {
        crate::secret::resolve(
            self.aes_secret.clone(),
            self.aes_secret_file.as_deref(),
            "--aes-secret",
            "--aes-secret-file",
            "PROXLET_AES_SECRET",
        )
    }

    /// Resolve the upstream URL from the flag, file, or environment.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed command-line options.
    ///
    /// # Returns
    ///
    /// Returns the upstream URL, or `None` when traffic is direct.
    ///
    /// # Errors
    ///
    /// Returns an error when more than one proxy source is set, the file is
    /// unsafe, or the URL cannot be parsed. The URL text is not included.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let upstream = cli.resolved_upstream()?;
    /// ```
    pub(crate) fn resolved_upstream(&self) -> Result<Option<Url>> {
        let from_file = self
            .proxy_file
            .as_deref()
            .map(crate::secret::read_owner_file)
            .transpose()?;
        let from_env = crate::secret::env_value("PROXLET_PROXY")?;
        let text = match (&self.proxy, from_file, from_env) {
            (Some(url), None, None) => return Ok(Some(url.clone())),
            (None, Some(text), None) | (None, None, Some(text)) => text,
            (None, None, None) => return Ok(None),
            (flag, file, env) => {
                let mut sources = Vec::new();
                if flag.is_some() {
                    sources.push("--proxy");
                }
                if file.is_some() {
                    sources.push("--proxy-file");
                }
                if env.is_some() {
                    sources.push("PROXLET_PROXY");
                }
                bail!("{} are mutually exclusive", sources.join(" and "))
            }
        };
        Url::parse(&text)
            .map(Some)
            .context("invalid upstream proxy URL")
    }

    /// Fail before spawn when a secret file or environment source is unsafe.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed command-line options.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` when every configured secret source can be read.
    ///
    /// # Errors
    ///
    /// Returns an error from password, AES secret, or upstream resolution.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// cli.check_secret_sources()?;
    /// ```
    pub(crate) fn check_secret_sources(&self) -> Result<()> {
        self.require_upstream_for_ca()?;
        let _ = self.resolved_password()?;
        let _ = self.resolved_aes_secret()?;
        let _ = self.resolved_upstream()?;
        Ok(())
    }

    /// Reject a CA bundle that has no upstream proxy source.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed command-line options.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` when `--proxy-ca` is absent or an upstream source is set.
    ///
    /// # Errors
    ///
    /// Returns an error when `--proxy-ca` is set without `--proxy`,
    /// `--proxy-file`, or `PROXLET_PROXY`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// cli.require_upstream_for_ca()?;
    /// ```
    fn require_upstream_for_ca(&self) -> Result<()> {
        if self.proxy_ca.is_none()
            || self.proxy.is_some()
            || self.proxy_file.is_some()
            || crate::secret::env_value("PROXLET_PROXY")?.is_some()
        {
            return Ok(());
        }
        bail!("--proxy-ca requires --proxy")
    }

    /// Names of flags whose values are still visible in process arguments.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed command-line options.
    ///
    /// # Returns
    ///
    /// Returns flag names that put a secret on the command line.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let flags = cli.visible_secret_flags();
    /// ```
    pub(crate) fn visible_secret_flags(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        if self.password.is_some() {
            flags.push("--auth");
        }
        if self.aes_secret.is_some() {
            flags.push("--aes-secret");
        }
        if self.proxy.as_ref().is_some_and(url_has_userinfo) {
            flags.push("--proxy");
        }
        flags
    }
}

/// Report whether a URL carries userinfo that would be visible in argv.
///
/// # Parameters
///
/// * `url` - Upstream URL.
///
/// # Returns
///
/// Returns true when the URL has a username or password.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let leaks = url_has_userinfo(&url);
/// ```
fn url_has_userinfo(url: &Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
}
