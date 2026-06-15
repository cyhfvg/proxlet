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

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxStream = Box<dyn AsyncStream>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    pub fn authority(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Clone, Debug)]
struct Credentials {
    username: String,
    password: String,
}

#[derive(Clone, Debug)]
struct Endpoint {
    target: Target,
    credentials: Option<Credentials>,
}

#[derive(Clone, Debug)]
struct SshEndpoint {
    target: Target,
    auth: SshAuthentication,
}

#[derive(Clone, Debug)]
struct SshAuthentication {
    username: String,
    method: SshAuthenticationMethod,
}

#[derive(Clone, Debug)]
enum SshAuthenticationMethod {
    Password(String),
    PrivateKey {
        path: PathBuf,
        passphrase: Option<String>,
    },
}

#[derive(Clone, Debug)]
enum Upstream {
    Http(Endpoint),
    Https(Endpoint),
    Socks5 {
        endpoint: Endpoint,
        remote_dns: bool,
    },
    FakeHttp {
        endpoint: Endpoint,
        aes_secret: Option<String>,
    },
    Ssh(SshEndpoint),
}

#[derive(Clone)]
pub struct Connector {
    upstream: Option<Upstream>,
    tls: Arc<ClientConfig>,
    fakehttp_max_frame_size: usize,
}

impl Connector {
    pub fn new(url: Option<Url>, upstream_ca: Option<&Path>) -> Result<Self> {
        Self::with_fakehttp_max_frame_size(url, upstream_ca, fakehttp::DEFAULT_MAX_FRAME_SIZE)
    }

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

    async fn tls_connect(&self, stream: TcpStream, host: &str) -> Result<BoxStream> {
        let name = ServerName::try_from(host.to_owned())
            .with_context(|| format!("invalid TLS server name {host}"))?;
        let stream = TlsConnector::from(self.tls.clone())
            .connect(name, stream)
            .await?;
        Ok(Box::new(stream))
    }
}

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

fn credentials(url: &Url) -> Result<Option<Credentials>> {
    if url.username().is_empty() {
        return Ok(None);
    }
    let username = decode_url_component(url.username())?;
    let password = decode_url_component(url.password().unwrap_or_default())?;
    Ok(Some(Credentials { username, password }))
}

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

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

fn decode_url_component(value: &str) -> Result<String> {
    Ok(percent_decode_str(value).decode_utf8()?.into_owned())
}

fn fakehttp_secret(url: &Url) -> Result<Option<String>> {
    let username = url.username();
    let password = url.password();
    match (username.is_empty(), password) {
        (_, Some(password)) => Ok(Some(decode_url_component(password)?)),
        (false, None) => Ok(Some(decode_url_component(username)?)),
        (true, None) => Ok(None),
    }
}

async fn connect_tcp(target: &Target) -> Result<TcpStream> {
    TcpStream::connect((target.host.as_str(), target.port))
        .await
        .with_context(|| format!("could not connect to {}", target.authority()))
}

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

fn sized_bytes<'a>(value: &'a str, label: &str) -> Result<&'a [u8]> {
    let bytes = value.as_bytes();
    if bytes.len() > u8::MAX as usize {
        bail!("{label} is too long")
    }
    Ok(bytes)
}

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
struct SshHandler;

impl client::Handler for SshHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

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
