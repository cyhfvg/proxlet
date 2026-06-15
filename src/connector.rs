//! Upstream connection management for direct and chained proxy traffic.
//!
//! The connector hides direct TCP dialing, HTTP/HTTPS CONNECT, SOCKS5,
//! fakehttp, and SSH upstream setup behind one async `connect` operation.

use std::fs::File;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use percent_encoding::percent_decode_str;
use russh::client;
use russh::keys::{Algorithm, HashAlg, PrivateKeyWithHashAlg};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use url::Url;

use crate::fakehttp;

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

#[derive(Clone, Debug)]
/// Username/password pair decoded from an upstream URL.
struct Credentials {
    username: String,
    password: String,
}

#[derive(Clone, Debug)]
/// Upstream proxy endpoint plus optional credentials.
struct Endpoint {
    target: Target,
    credentials: Option<Credentials>,
}

#[derive(Clone, Debug)]
/// SSH upstream endpoint plus its authentication configuration.
struct SshEndpoint {
    target: Target,
    auth: SshAuthentication,
}

#[derive(Clone, Debug)]
/// SSH username and authentication method.
struct SshAuthentication {
    username: String,
    method: SshAuthenticationMethod,
}

#[derive(Clone, Debug)]
/// Authentication methods supported for SSH upstream proxying.
enum SshAuthenticationMethod {
    /// Password authentication.
    Password(String),
    /// Public-key authentication with optional key passphrase.
    PrivateKey {
        path: PathBuf,
        passphrase: Option<String>,
    },
}

#[derive(Clone, Debug)]
/// Parsed upstream proxy configuration.
enum Upstream {
    /// Plain HTTP CONNECT upstream proxy.
    Http(Endpoint),
    /// HTTPS CONNECT upstream proxy.
    Https(Endpoint),
    /// SOCKS5 upstream proxy.
    Socks5 {
        endpoint: Endpoint,
        remote_dns: bool,
    },
    /// fakehttp proxlet-to-proxlet upstream.
    FakeHttp {
        endpoint: Endpoint,
        aes_secret: Option<String>,
    },
    /// SSH direct-tcpip upstream proxy.
    Ssh(SshEndpoint),
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

/// Add PEM CA certificates to a rustls root store.
///
/// # Parameters
///
/// * `roots` - Root certificate store to extend.
/// * `path` - PEM file containing one or more CA certificates.
///
/// # Returns
///
/// Returns `Ok(())` after all certificates are added.
///
/// # Errors
///
/// Returns an error when the file cannot be opened, contains no certificates,
/// contains invalid PEM, or a certificate cannot be accepted by rustls.
fn add_ca_certificates(roots: &mut RootCertStore, path: &Path) -> Result<()> {
    let mut reader = BufReader::new(
        File::open(path)
            .with_context(|| format!("could not open upstream proxy CA {}", path.display()))?,
    );
    let certs = rustls_pemfile::certs(&mut reader).collect::<io::Result<Vec<_>>>()?;
    if certs.is_empty() {
        bail!(
            "upstream proxy CA file contains no certificates: {}",
            path.display()
        )
    }
    for certificate in certs {
        roots.add(certificate).with_context(|| {
            format!(
                "invalid certificate in upstream proxy CA file {}",
                path.display()
            )
        })?;
    }
    Ok(())
}

/// Parse an upstream proxy URL into an internal upstream configuration.
///
/// # Parameters
///
/// * `url` - User-provided upstream proxy URL.
///
/// # Returns
///
/// Returns a parsed [`Upstream`] variant.
///
/// # Errors
///
/// Returns an error when the URL is missing host or port information, uses an
/// unsupported scheme, has malformed credentials, or has invalid SSH options.
fn parse_upstream(url: Url) -> Result<Upstream> {
    let target = Target::new(
        url.host_str()
            .ok_or_else(|| anyhow::anyhow!("upstream proxy URL has no host"))?,
        url.port_or_known_default()
            .ok_or_else(|| anyhow::anyhow!("upstream proxy URL has no port"))?,
    );
    let endpoint = Endpoint {
        target: target.clone(),
        credentials: credentials(&url)?,
    };
    match url.scheme() {
        "http" => Ok(Upstream::Http(endpoint)),
        "https" => Ok(Upstream::Https(endpoint)),
        "socks5" => Ok(Upstream::Socks5 {
            endpoint,
            remote_dns: false,
        }),
        "socks5h" => Ok(Upstream::Socks5 {
            endpoint,
            remote_dns: true,
        }),
        "fakehttp" => Ok(Upstream::FakeHttp {
            endpoint,
            aes_secret: fakehttp_secret(&url)?,
        }),
        "ssh" => Ok(Upstream::Ssh(parse_ssh_upstream(target, &url)?)),
        schema => bail!("unsupported upstream proxy scheme: {schema}"),
    }
}

/// Decode username/password credentials from a URL.
///
/// # Parameters
///
/// * `url` - Upstream URL containing optional userinfo.
///
/// # Returns
///
/// Returns decoded credentials or `None` when no username was supplied.
///
/// # Errors
///
/// Returns an error when percent-decoding or UTF-8 decoding fails.
fn credentials(url: &Url) -> Result<Option<Credentials>> {
    if url.username().is_empty() {
        return Ok(None);
    }
    let username = decode_url_component(url.username())?;
    let password = decode_url_component(url.password().unwrap_or_default())?;
    Ok(Some(Credentials { username, password }))
}

/// Parse SSH-specific upstream authentication settings.
///
/// # Parameters
///
/// * `target` - SSH server endpoint.
/// * `url` - SSH upstream URL.
///
/// # Returns
///
/// Returns an [`SshEndpoint`] with a selected authentication method.
///
/// # Errors
///
/// Returns an error when required username/password/key data is missing or
/// malformed.
fn parse_ssh_upstream(target: Target, url: &Url) -> Result<SshEndpoint> {
    let credentials = credentials(url)?;
    let identity = ssh_identity_path(url)?;
    let auth = match (credentials, identity) {
        (Some(credentials), Some(path)) => SshAuthentication {
            username: credentials.username,
            method: SshAuthenticationMethod::PrivateKey {
                path,
                passphrase: non_empty(credentials.password),
            },
        },
        (Some(credentials), None) if !credentials.password.is_empty() => SshAuthentication {
            username: credentials.username,
            method: SshAuthenticationMethod::Password(credentials.password),
        },
        (Some(_), None) => bail!("ssh password authentication requires a password"),
        (None, Some(_)) => bail!("ssh private-key authentication requires a username"),
        (None, None) => bail!("ssh upstream URL requires username and password or ?key=<file>"),
    };
    Ok(SshEndpoint { target, auth })
}

/// Extract an SSH identity file path from URL query parameters.
///
/// # Parameters
///
/// * `url` - SSH upstream URL.
///
/// # Returns
///
/// Returns an optional private key path.
///
/// # Errors
///
/// Returns an error when a recognized key parameter is present but empty.
fn ssh_identity_path(url: &Url) -> Result<Option<PathBuf>> {
    for (name, value) in url.query_pairs() {
        if matches!(name.as_ref(), "key" | "identity" | "identity_file") {
            if value.is_empty() {
                bail!("ssh private key path is empty")
            }
            return Ok(Some(PathBuf::from(value.into_owned())));
        }
    }
    Ok(None)
}

/// Convert an empty string into `None`.
///
/// # Parameters
///
/// * `value` - Owned string to inspect.
///
/// # Returns
///
/// Returns `Some(value)` when non-empty, otherwise `None`.
///
/// # Errors
///
/// This function does not return errors.
fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

/// Percent-decode a URL component into UTF-8 text.
///
/// # Parameters
///
/// * `value` - Percent-encoded URL component.
///
/// # Returns
///
/// Returns a decoded string.
///
/// # Errors
///
/// Returns an error when the decoded bytes are not valid UTF-8.
fn decode_url_component(value: &str) -> Result<String> {
    Ok(percent_decode_str(value).decode_utf8()?.into_owned())
}

/// Extract the fakehttp AES secret from an upstream URL.
///
/// # Parameters
///
/// * `url` - fakehttp upstream URL.
///
/// # Returns
///
/// Returns the decoded secret from password or username userinfo, or `None`.
///
/// # Errors
///
/// Returns an error when secret percent-decoding fails.
fn fakehttp_secret(url: &Url) -> Result<Option<String>> {
    let username = url.username();
    let password = url.password();
    match (username.is_empty(), password) {
        (_, Some(password)) => Ok(Some(decode_url_component(password)?)),
        (false, None) => Ok(Some(decode_url_component(username)?)),
        (true, None) => Ok(None),
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

/// Establish an HTTP CONNECT tunnel through an upstream proxy.
///
/// # Parameters
///
/// * `stream` - Connected upstream proxy stream.
/// * `target` - Final destination authority.
/// * `credentials` - Optional upstream Basic authentication credentials.
///
/// # Returns
///
/// Returns `Ok(())` once the upstream proxy reports tunnel establishment.
///
/// # Errors
///
/// Returns an error when writing the request, reading the response, parsing the
/// response status, or receiving a non-200 status fails.
async fn establish_http_tunnel(
    stream: &mut BoxStream,
    target: &Target,
    credentials: Option<&Credentials>,
) -> Result<()> {
    let mut request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
        target.authority(),
        target.authority()
    );
    if let Some(auth) = credentials {
        let token = BASE64.encode(format!("{}:{}", auth.username, auth.password));
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let header = read_header(stream, 16 * 1024).await?;
    let status = std::str::from_utf8(&header)?
        .lines()
        .next()
        .unwrap_or_default();
    if !status.contains(" 200 ") {
        bail!("upstream HTTP proxy rejected CONNECT: {status}")
    }
    Ok(())
}

/// Establish a SOCKS5 CONNECT tunnel through an upstream proxy.
///
/// # Parameters
///
/// * `stream` - Connected upstream SOCKS5 proxy stream.
/// * `target` - Final destination.
/// * `credentials` - Optional username/password credentials.
/// * `remote_dns` - Whether to send the hostname to the upstream proxy.
///
/// # Returns
///
/// Returns `Ok(())` once the SOCKS5 proxy has connected to the target.
///
/// # Errors
///
/// Returns an error when authentication, DNS resolution, request writing, or
/// proxy response parsing fails.
async fn socks_connect(
    stream: &mut BoxStream,
    target: &Target,
    credentials: Option<&Credentials>,
    remote_dns: bool,
) -> Result<()> {
    let methods = if credentials.is_some() {
        &[0x00, 0x02][..]
    } else {
        &[0x00][..]
    };
    stream.write_all(&[0x05, methods.len() as u8]).await?;
    stream.write_all(methods).await?;
    let mut selected = [0_u8; 2];
    stream.read_exact(&mut selected).await?;
    if selected[0] != 0x05 || selected[1] == 0xff {
        bail!("upstream SOCKS5 proxy rejected authentication methods")
    }
    if selected[1] == 0x02 {
        let auth = credentials
            .ok_or_else(|| anyhow::anyhow!("upstream SOCKS5 proxy requested credentials"))?;
        let username = sized_bytes(&auth.username, "SOCKS username")?;
        let password = sized_bytes(&auth.password, "SOCKS password")?;
        stream.write_all(&[0x01, username.len() as u8]).await?;
        stream.write_all(username).await?;
        stream.write_all(&[password.len() as u8]).await?;
        stream.write_all(password).await?;
        stream.read_exact(&mut selected).await?;
        if selected != [0x01, 0x00] {
            bail!("upstream SOCKS5 authentication failed")
        }
    }
    let mut request = vec![0x05, 0x01, 0x00];
    if remote_dns {
        let host = sized_bytes(&target.host, "target host")?;
        request.push(0x03);
        request.push(host.len() as u8);
        request.extend_from_slice(host);
    } else {
        let mut addresses = tokio::net::lookup_host((target.host.as_str(), target.port)).await?;
        let address = addresses
            .next()
            .ok_or_else(|| anyhow::anyhow!("could not resolve {}", target.host))?;
        match address.ip() {
            std::net::IpAddr::V4(ip) => {
                request.push(0x01);
                request.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                request.push(0x04);
                request.extend_from_slice(&ip.octets());
            }
        }
    }
    request.extend_from_slice(&target.port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 0x05 || response[1] != 0x00 {
        bail!(
            "upstream SOCKS5 connection failed with status {}",
            response[1]
        )
    }
    discard_socks_address(stream, response[3]).await?;
    Ok(())
}

/// Borrow a string as SOCKS-sized bytes.
///
/// # Parameters
///
/// * `value` - String value to encode.
/// * `label` - Human-readable field name for error messages.
///
/// # Returns
///
/// Returns the borrowed byte slice when it fits in a one-byte length field.
///
/// # Errors
///
/// Returns an error when `value` is longer than 255 bytes.
fn sized_bytes<'a>(value: &'a str, label: &str) -> Result<&'a [u8]> {
    let bytes = value.as_bytes();
    if bytes.len() > u8::MAX as usize {
        bail!("{label} is too long")
    }
    Ok(bytes)
}

/// Read and discard the bound address from a SOCKS5 response.
///
/// # Parameters
///
/// * `stream` - Upstream SOCKS5 stream.
/// * `address_type` - SOCKS5 address type byte from the response header.
///
/// # Returns
///
/// Returns `Ok(())` after the address and port are consumed.
///
/// # Errors
///
/// Returns an error when the address type is invalid or the response ends early.
async fn discard_socks_address(stream: &mut BoxStream, address_type: u8) -> Result<()> {
    let size = match address_type {
        0x01 => 4,
        0x03 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            length[0] as usize
        }
        0x04 => 16,
        _ => bail!("upstream SOCKS5 proxy returned an invalid address type"),
    };
    let mut address_and_port = vec![0_u8; size + 2];
    stream.read_exact(&mut address_and_port).await?;
    Ok(())
}

/// Read an HTTP-style header until CRLFCRLF or a size limit.
///
/// # Parameters
///
/// * `stream` - Stream to read from.
/// * `limit` - Maximum accepted header size in bytes.
///
/// # Returns
///
/// Returns the complete header bytes including the terminating CRLFCRLF.
///
/// # Errors
///
/// Returns an error when the header exceeds `limit`, the stream ends early, or
/// I/O fails.
async fn read_header(stream: &mut BoxStream, limit: usize) -> Result<Vec<u8>> {
    let mut header = Vec::with_capacity(256);
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= limit {
            bail!("proxy response header exceeds {limit} bytes")
        }
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await?;
        header.push(byte[0]);
    }
    Ok(header)
}

#[derive(Clone)]
/// SSH client handler used for upstream sessions.
struct SshHandler;

impl client::Handler for SshHandler {
    type Error = anyhow::Error;

    /// Accept any SSH server host key.
    ///
    /// # Parameters
    ///
    /// * `self` - Mutable SSH handler state.
    /// * `_key` - Server public key presented during SSH handshake.
    ///
    /// # Returns
    ///
    /// Returns `true` to allow the connection.
    ///
    /// # Errors
    ///
    /// This handler does not return validation errors.
    async fn check_server_key(
        &mut self,
        _key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Establish an SSH direct-tcpip channel to a target.
///
/// # Parameters
///
/// * `endpoint` - SSH upstream endpoint and credentials.
/// * `target` - Final destination for the direct-tcpip channel.
///
/// # Returns
///
/// Returns a boxed SSH channel stream.
///
/// # Errors
///
/// Returns an error when SSH connection, authentication, key loading, or channel
/// opening fails.
async fn ssh_connect(endpoint: &SshEndpoint, target: &Target) -> Result<BoxStream> {
    let config = Arc::new(client::Config {
        nodelay: true,
        ..Default::default()
    });
    let mut session = client::connect(
        config,
        (endpoint.target.host.as_str(), endpoint.target.port),
        SshHandler,
    )
    .await
    .context("could not establish SSH upstream session")?;
    let authenticated = match &endpoint.auth.method {
        SshAuthenticationMethod::Password(password) => session
            .authenticate_password(endpoint.auth.username.clone(), password.clone())
            .await?
            .success(),
        SshAuthenticationMethod::PrivateKey { path, passphrase } => {
            let key = Arc::new(
                russh::keys::load_secret_key(path, passphrase.as_deref()).with_context(|| {
                    format!("could not load SSH private key {}", path.display())
                })?,
            );
            authenticate_private_key(&mut session, endpoint.auth.username.clone(), key).await?
        }
    };
    if !authenticated {
        bail!("SSH upstream authentication failed")
    }
    let channel = session
        .channel_open_direct_tcpip(target.host.clone(), target.port.into(), "127.0.0.1", 0)
        .await
        .with_context(|| format!("SSH server could not forward to {}", target.authority()))?;
    Ok(Box::new(channel.into_stream()))
}

/// Try public-key authentication with compatible hash algorithms.
///
/// # Parameters
///
/// * `session` - Connected SSH client session.
/// * `username` - SSH username.
/// * `key` - Private key used for authentication.
///
/// # Returns
///
/// Returns `true` when one authentication attempt succeeds.
///
/// # Errors
///
/// Returns an error when querying server algorithms or an authentication attempt
/// fails at the protocol level.
async fn authenticate_private_key(
    session: &mut client::Handle<SshHandler>,
    username: String,
    key: Arc<russh::keys::PrivateKey>,
) -> Result<bool> {
    let key_algorithm = key.algorithm();
    let server_rsa_hash = if matches!(key_algorithm, Algorithm::Rsa { .. }) {
        session.best_supported_rsa_hash().await?
    } else {
        None
    };
    for hash_alg in publickey_hash_algorithms(key_algorithm, server_rsa_hash) {
        let result = session
            .authenticate_publickey(
                username.clone(),
                PrivateKeyWithHashAlg::new(key.clone(), hash_alg),
            )
            .await?;
        if result.success() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Choose SSH public-key hash algorithms for an authentication attempt.
///
/// # Parameters
///
/// * `key_algorithm` - Algorithm of the loaded private key.
/// * `server_rsa_hash` - RSA signature algorithm advertised by the SSH server.
///
/// # Returns
///
/// Returns ordered hash algorithm candidates to try.
///
/// # Errors
///
/// This function does not return errors.
fn publickey_hash_algorithms(
    key_algorithm: Algorithm,
    server_rsa_hash: Option<Option<HashAlg>>,
) -> Vec<Option<HashAlg>> {
    if !matches!(key_algorithm, Algorithm::Rsa { .. }) {
        return vec![None];
    }

    match server_rsa_hash {
        Some(hash_alg) => vec![hash_alg],
        None => vec![Some(HashAlg::Sha512), Some(HashAlg::Sha256), None],
    }
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
/// Returns `Ok(())` after both directions finish copying.
///
/// # Errors
///
/// Returns I/O errors from either stream.
pub async fn relay(mut client: BoxStream, mut remote: BoxStream) -> io::Result<()> {
    tokio::io::copy_bidirectional(&mut client, &mut remote)
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_ipv6_authority() {
        assert_eq!(Target::new("::1", 443).authority(), "[::1]:443");
    }

    #[test]
    fn accepts_ssh_upstream_url() {
        let url = Url::parse("ssh://user:password@localhost:22").expect("URL");
        assert!(matches!(parse_upstream(url), Ok(Upstream::Ssh(_))));
    }

    #[test]
    fn accepts_fakehttp_upstream_url_with_aes_secret() {
        let url = Url::parse("fakehttp://secret@localhost:8080").expect("URL");
        let upstream = parse_upstream(url).expect("upstream");

        match upstream {
            Upstream::FakeHttp { aes_secret, .. } => {
                assert_eq!(aes_secret.as_deref(), Some("secret"));
            }
            _ => panic!("expected fakehttp upstream"),
        }
    }

    #[test]
    fn accepts_ssh_upstream_private_key_url() {
        let url =
            Url::parse("ssh://user@localhost:22?key=/home/user/.ssh/id_ed25519").expect("URL");
        let upstream = parse_upstream(url).expect("upstream");

        match upstream {
            Upstream::Ssh(endpoint) => {
                assert_eq!(endpoint.auth.username, "user");
                assert!(matches!(
                    endpoint.auth.method,
                    SshAuthenticationMethod::PrivateKey { .. }
                ));
            }
            _ => panic!("expected SSH upstream"),
        }
    }

    #[test]
    fn tries_rsa_sha2_when_server_does_not_advertise_signature_algorithms() {
        assert_eq!(
            publickey_hash_algorithms(Algorithm::Rsa { hash: None }, None),
            vec![Some(HashAlg::Sha512), Some(HashAlg::Sha256), None,]
        );
    }

    #[test]
    fn uses_server_advertised_rsa_signature_algorithm() {
        assert_eq!(
            publickey_hash_algorithms(Algorithm::Rsa { hash: None }, Some(Some(HashAlg::Sha256))),
            vec![Some(HashAlg::Sha256)]
        );
        assert_eq!(
            publickey_hash_algorithms(Algorithm::Rsa { hash: None }, Some(None)),
            vec![None]
        );
    }

    #[test]
    fn ignores_hash_algorithm_for_non_rsa_keys() {
        assert_eq!(
            publickey_hash_algorithms(Algorithm::Ed25519, Some(Some(HashAlg::Sha512))),
            vec![None]
        );
    }
}
