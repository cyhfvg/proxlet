use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use percent_encoding::percent_decode_str;
use russh::client;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use url::Url;

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
enum Upstream {
    Http(Endpoint),
    Https(Endpoint),
    Socks5 {
        endpoint: Endpoint,
        remote_dns: bool,
    },
    Ssh(Endpoint),
}

#[derive(Clone)]
pub struct Connector {
    upstream: Option<Upstream>,
    tls: Arc<ClientConfig>,
}

impl Connector {
    pub fn new(url: Option<Url>, upstream_ca: Option<&Path>) -> Result<Self> {
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
    let endpoint = Endpoint {
        target: Target::new(
            url.host_str()
                .ok_or_else(|| anyhow::anyhow!("upstream proxy URL has no host"))?,
            url.port_or_known_default()
                .ok_or_else(|| anyhow::anyhow!("upstream proxy URL has no port"))?,
        ),
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
        "ssh" => {
            if endpoint.credentials.is_none() {
                bail!("ssh upstream URL requires username and password")
            }
            Ok(Upstream::Ssh(endpoint))
        }
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

fn decode_url_component(value: &str) -> Result<String> {
    Ok(percent_decode_str(value).decode_utf8()?.into_owned())
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

async fn ssh_connect(endpoint: &Endpoint, target: &Target) -> Result<BoxStream> {
    let auth = endpoint
        .credentials
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ssh upstream credentials are required"))?;
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
    let result = session
        .authenticate_password(auth.username.clone(), auth.password.clone())
        .await?;
    if !result.success() {
        bail!("SSH upstream authentication failed")
    }
    let channel = session
        .channel_open_direct_tcpip(target.host.clone(), target.port.into(), "127.0.0.1", 0)
        .await
        .with_context(|| format!("SSH server could not forward to {}", target.authority()))?;
    Ok(Box::new(channel.into_stream()))
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
}
