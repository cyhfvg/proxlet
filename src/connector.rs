//! Upstream connection management for direct and chained proxy traffic.
//!
//! The connector hides direct TCP dialing, HTTP/HTTPS CONNECT, SOCKS5,
//! fakehttp, and SSH upstream setup behind one async `connect` operation.

use std::io;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use url::Url;

use crate::fakehttp;

mod protocol;
mod ssh;
mod upstream;

use protocol::{establish_http_tunnel, socks_connect};
use ssh::ssh_connect;
use upstream::{Upstream, add_ca_certificates, parse_upstream};

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
}

#[derive(Clone)]
/// Connection factory for direct traffic or a configured upstream proxy chain.
pub struct Connector {
    upstream: Option<Upstream>,
    tls: Arc<ClientConfig>,
    fakehttp_max_frame_size: usize,
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
            fakehttp_max_frame_size,
        })
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
        match &self.upstream {
            None => Ok(Box::new(connect_tcp(target).await?)),
            Some(Upstream::Http(endpoint)) => {
                let mut stream: BoxStream = Box::new(connect_tcp(&endpoint.target).await?);
                establish_http_tunnel(&mut stream, target, endpoint.credentials.as_ref()).await?;
                Ok(stream)
            }
            Some(Upstream::Https(endpoint)) => {
                let tcp = connect_tcp(&endpoint.target).await?;
                let mut stream = self.tls_connect(tcp, &endpoint.target.host).await?;
                establish_http_tunnel(&mut stream, target, endpoint.credentials.as_ref()).await?;
                Ok(stream)
            }
            Some(Upstream::Socks5 {
                endpoint,
                remote_dns,
            }) => {
                let mut stream: BoxStream = Box::new(connect_tcp(&endpoint.target).await?);
                socks_connect(
                    &mut stream,
                    target,
                    endpoint.credentials.as_ref(),
                    *remote_dns,
                )
                .await?;
                Ok(stream)
            }
            Some(Upstream::Ssh(endpoint)) => ssh_connect(endpoint, target).await,
            Some(Upstream::FakeHttp {
                endpoint,
                aes_secret,
            }) => {
                let stream: BoxStream = Box::new(connect_tcp(&endpoint.target).await?);
                fakehttp::connect(
                    stream,
                    &endpoint.target,
                    target,
                    aes_secret.as_deref(),
                    self.fakehttp_max_frame_size,
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
        let stream = TlsConnector::from(self.tls.clone())
            .connect(name, stream)
            .await?;
        Ok(Box::new(stream))
    }
}

/// Open a direct TCP connection to a target.
///
/// # Parameters
///
/// * `target` - Destination host and port.
///
/// # Returns
///
/// Returns an established [`TcpStream`].
///
/// # Errors
///
/// Returns an error when DNS resolution or TCP connection fails.
async fn connect_tcp(target: &Target) -> Result<TcpStream> {
    TcpStream::connect((target.host.as_str(), target.port))
        .await
        .with_context(|| format!("could not connect to {}", target.authority()))
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
