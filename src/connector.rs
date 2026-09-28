//! Upstream connection management for direct and chained proxy traffic.
//!
//! The connector hides direct TCP dialing, HTTP/HTTPS CONNECT, SOCKS5,
//! fakehttp, and SSH upstream setup behind one async `connect` operation.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use url::Url;

use crate::fakehttp;

mod protocol;
mod socks;
mod ssh;
mod upstream;

use protocol::establish_http_tunnel;
use socks::open_socks5;
use ssh::{open_ssh_channel, SshSessions};
use upstream::{add_ca_certificates, parse_upstream, Upstream};

/// Async stream requirements shared by all proxlet transport implementations.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Boxed async stream used when the concrete transport type is selected at runtime.
pub type BoxStream = Box<dyn AsyncStream>;

#[derive(Clone, Debug, Eq, PartialEq)]
/// A network endpoint resolved as host and port.
pub struct Target {
    /// Hostname or IP address.
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl Target {
    /// Build a target from host and port components.
    ///
    /// # Parameters
    ///
    /// * `host` - Hostname or IP address.
    /// * `port` - TCP port.
    ///
    /// # Returns
    ///
    /// Returns a new [`Target`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// Format the endpoint as an HTTP authority.
    ///
    /// # Parameters
    ///
    /// * `self` - Target to format.
    ///
    /// # Returns
    ///
    /// Returns `host:port`, with IPv6 hosts wrapped in brackets.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    pub fn authority(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Reject text that would break out of an HTTP header line.
    ///
    /// # Parameters
    ///
    /// * `value` - Host or authority that may be spliced into an HTTP request.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` when the text contains no control characters.
    ///
    /// # Errors
    ///
    /// Returns an error when the text contains CR, LF, NUL, or another control
    /// character. The error does not include `value`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// Target::reject_control_chars("example.com")?;
    /// ```
    pub(crate) fn reject_control_chars(value: &str) -> Result<()> {
        if value.chars().any(char::is_control) {
            bail!("host contains a control character");
        }
        Ok(())
    }
}

#[derive(Clone)]
/// Connection factory for direct traffic or a configured upstream proxy chain.
pub struct Connector {
    upstream: Option<Upstream>,
    tls: Arc<ClientConfig>,
    ssh_sessions: Arc<SshSessions>,
    fakehttp_max_frame_size: usize,
    connect_timeout: Duration,
}

impl Connector {
    /// Create a connector with the default fakehttp frame size.
    ///
    /// # Parameters
    ///
    /// * `url` - Optional upstream proxy URL.
    /// * `upstream_ca` - Optional CA bundle for HTTPS upstream verification.
    ///
    /// # Returns
    ///
    /// Returns a configured [`Connector`].
    ///
    /// # Errors
    ///
    /// Returns an error when the upstream URL is unsupported, credentials cannot
    /// be decoded, SSH options are invalid, or the CA bundle cannot be loaded.
    pub fn new(url: Option<Url>, upstream_ca: Option<&Path>) -> Result<Self> {
        Self::with_fakehttp_max_frame_size(url, upstream_ca, fakehttp::DEFAULT_MAX_FRAME_SIZE)
    }

    /// Create a connector with an explicit fakehttp frame size.
    ///
    /// # Parameters
    ///
    /// * `url` - Optional upstream proxy URL.
    /// * `upstream_ca` - Optional CA bundle for HTTPS upstream verification.
    /// * `fakehttp_max_frame_size` - Maximum fakehttp payload frame size in bytes.
    ///
    /// # Returns
    ///
    /// Returns a configured [`Connector`].
    ///
    /// # Errors
    ///
    /// Returns an error when upstream parsing or CA loading fails.
    pub fn with_fakehttp_max_frame_size(
        url: Option<Url>,
        upstream_ca: Option<&Path>,
        fakehttp_max_frame_size: usize,
    ) -> Result<Self> {
        let upstream = url.map(parse_upstream).transpose()?;
        let mut roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        if let Some(path) = upstream_ca {
            add_ca_certificates(&mut roots, path)?;
        }
        let tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            upstream,
            tls: Arc::new(tls),
            ssh_sessions: Arc::new(SshSessions::new()),
            fakehttp_max_frame_size,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        })
    }

    /// Replace the DNS, TCP dial, and handshake deadline.
    ///
    /// # Parameters
    ///
    /// * `self` - Connector to update.
    /// * `timeout` - Per-attempt deadline. This is not an idle timeout for an
    ///   established tunnel.
    ///
    /// # Returns
    ///
    /// Returns the connector with the timeout replaced.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let connector = Connector::new(None, None)?
    ///     .with_connect_timeout(Duration::from_secs(5));
    /// ```
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Return the configured DNS, dial, and handshake deadline.
    ///
    /// # Returns
    ///
    /// Returns the per-attempt timeout. Established tunnels are not affected.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let timeout = connector.connect_timeout();
    /// ```
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Connect to a target through the configured upstream path.
    ///
    /// # Parameters
    ///
    /// * `self` - Connector configuration and TLS client state.
    /// * `target` - Final destination requested by the client.
    ///
    /// # Returns
    ///
    /// Returns an established bidirectional stream to `target`.
    ///
    /// # Errors
    ///
    /// Returns an error when TCP dialing, TLS negotiation, proxy handshakes,
    /// fakehttp negotiation, or SSH forwarding fails.
    pub async fn connect(&self, target: &Target) -> Result<BoxStream> {
        let timeout = self.connect_timeout;
        match &self.upstream {
            None => Ok(Box::new(connect_tcp(target, timeout).await?)),
            Some(Upstream::Http(endpoint)) => {
                let mut stream: BoxStream = Box::new(connect_tcp(&endpoint.target, timeout).await?);
                establish_http_tunnel(&mut stream, target, endpoint.credentials.as_ref(), timeout)
                    .await?;
                Ok(stream)
            }
            Some(Upstream::Https(endpoint)) => {
                let tcp = connect_tcp(&endpoint.target, timeout).await?;
                let mut stream = self.tls_connect(tcp, &endpoint.target.host).await?;
                establish_http_tunnel(&mut stream, target, endpoint.credentials.as_ref(), timeout)
                    .await?;
                Ok(stream)
            }
            Some(Upstream::Socks5 {
                endpoint,
                remote_dns,
            }) => open_socks5(endpoint, *remote_dns, target, timeout).await,
            Some(Upstream::Ssh(endpoint)) => {
                open_ssh_channel(&self.ssh_sessions, endpoint, target, timeout).await
            }
            Some(Upstream::FakeHttp {
                endpoint,
                aes_secret,
            }) => {
                let stream: BoxStream = Box::new(connect_tcp(&endpoint.target, timeout).await?);
                fakehttp::connect(
                    stream,
                    &endpoint.target,
                    target,
                    aes_secret.as_deref(),
                    self.fakehttp_max_frame_size,
                    timeout,
                )
                .await
            }
        }
    }

    /// Wrap a TCP stream in TLS for HTTPS upstream proxying.
    ///
    /// # Parameters
    ///
    /// * `self` - Connector containing the client TLS configuration.
    /// * `stream` - Connected TCP stream to the HTTPS proxy.
    /// * `host` - DNS name used for TLS verification.
    ///
    /// # Returns
    ///
    /// Returns a boxed TLS stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the server name is invalid or the TLS handshake
    /// fails.
    async fn tls_connect(&self, stream: TcpStream, host: &str) -> Result<BoxStream> {
        let name = ServerName::try_from(host.to_owned())
            .with_context(|| format!("invalid TLS server name {host}"))?;
        let stream = with_timeout(
            self.connect_timeout,
            "TLS handshake",
            TlsConnector::from(self.tls.clone()).connect(name, stream),
        )
        .await?;
        Ok(Box::new(stream))
    }
}

/// Default deadline for one DNS lookup, one TCP address, or one handshake phase.
pub(crate) const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Run `fut` and fail when it does not finish within `timeout`.
///
/// # Parameters
///
/// * `timeout` - Deadline for this attempt only.
/// * `what` - Lowercase label included in the timeout error.
/// * `fut` - Operation to bound. Dropping it does not cancel work that the
///   future already spawned.
///
/// # Returns
///
/// Returns the successful value of `fut`.
///
/// # Errors
///
/// Returns `fut`'s error, or `{what} timed out` when the deadline fires.
///
/// # Examples
///
/// ```ignore
/// let stream = with_timeout(timeout, "TCP connect", TcpStream::connect(addr)).await?;
/// ```
pub(crate) async fn with_timeout<T, E>(
    timeout: Duration,
    what: &str,
    fut: impl Future<Output = std::result::Result<T, E>>,
) -> Result<T>
where
    E: Into<anyhow::Error>,
{
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => bail!("{what} timed out"),
    }
}

/// Open a direct TCP connection to a target.
///
/// # Parameters
///
/// * `target` - Destination host and port.
/// * `timeout` - Deadline used once for DNS and again for each resolved address.
///
/// # Returns
///
/// Returns an established [`TcpStream`].
///
/// # Errors
///
/// Returns an error when DNS resolution or every TCP attempt fails.
///
/// # Examples
///
/// ```ignore
/// let stream = connect_tcp(&target, Duration::from_secs(10)).await?;
/// ```
async fn connect_tcp(target: &Target, timeout: Duration) -> Result<TcpStream> {
    let addrs = with_timeout(
        timeout,
        "DNS lookup",
        tokio::net::lookup_host((target.host.as_str(), target.port)),
    )
    .await
    .with_context(|| format!("could not resolve {}", target.host))?;
    let addrs: Vec<SocketAddr> = addrs.collect();
    if addrs.is_empty() {
        bail!("could not resolve {}", target.host);
    }
    connect_socket_addrs(addrs, timeout)
        .await
        .with_context(|| format!("could not connect to {}", target.authority()))
}

/// Dial addresses one at a time, each with a fresh timeout.
///
/// # Parameters
///
/// * `addrs` - Candidate socket addresses, in the order to try them.
/// * `timeout` - Deadline for each address. A timed-out address does not
///   consume the next address's deadline.
///
/// # Returns
///
/// Returns the first established stream with `TCP_NODELAY` enabled.
///
/// # Errors
///
/// Returns the last dial error, or an error when `addrs` is empty.
///
/// # Examples
///
/// ```ignore
/// let stream = connect_socket_addrs([first, second], Duration::from_millis(200)).await?;
/// ```

async fn connect_socket_addrs(
    addrs: impl IntoIterator<Item = SocketAddr>,
    timeout: Duration,
) -> Result<TcpStream> {
    let mut last_error = None;
    let mut tried = false;
    for addr in addrs {
        tried = true;
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                enable_tcp_nodelay(&stream)?;
                return Ok(stream);
            }
            Ok(Err(error)) => last_error = Some(anyhow::Error::from(error)),
            Err(_) => last_error = Some(anyhow::anyhow!("connect to {addr} timed out")),
        }
    }
    match last_error {
        Some(error) => Err(error),
        None if !tried => bail!("no address to dial"),
        None => bail!("no address to dial"),
    }
}

/// Disable Nagle on an established TCP socket.
///
/// # Parameters
///
/// * `stream` - Connected TCP socket.
///
/// # Returns
///
/// Returns `Ok(())` after `TCP_NODELAY` is enabled.
///
/// # Errors
///
/// Returns an error when the socket rejects the option.
///
/// # Examples
///
/// ```text
/// enable_tcp_nodelay(&stream)?;
/// ```
pub(crate) fn enable_tcp_nodelay(stream: &TcpStream) -> Result<()> {
    stream
        .set_nodelay(true)
        .context("could not enable TCP_NODELAY")
}

/// Relay bytes bidirectionally between a client stream and a remote stream.
///
/// # Parameters
///
/// * `client` - Client-side stream.
/// * `remote` - Remote target or upstream stream.
///
/// # Returns
///
/// Returns `Ok(())` after both directions finish copying. Buffered writes
/// accepted before `relay` are flushed first so a later `copy_bidirectional`
/// cannot leave them stranded in user space.
///
/// # Errors
///
/// Returns I/O errors from either stream.
pub async fn relay(mut client: BoxStream, mut remote: BoxStream) -> io::Result<()> {
    client.flush().await?;
    remote.flush().await?;
    tokio::io::copy_bidirectional(&mut client, &mut remote)
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_connector_defaults_to_ten_seconds() {
        let connector = Connector::new(None, None).expect("connector");
        assert_eq!(connector.connect_timeout(), Duration::from_secs(10));
    }

    #[tokio::test]
    async fn connect_falls_through_a_timed_out_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let local = listener.local_addr().expect("local address");
        let started = std::time::Instant::now();
        let stream = connect_socket_addrs(
            [
                SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
                    1,
                ),
                local,
            ],
            Duration::from_millis(200),
        )
        .await
        .expect("second address");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(stream.peer_addr().expect("peer"), local);
        assert!(stream.nodelay().expect("nodelay"));
    }
}
