use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use proxlet::{Cli, ProxyType};
use russh::keys::{Algorithm, PrivateKey, PublicKey, ssh_key};
use russh::server::{Auth, Handler, Msg, Server, Session};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use url::Url;

const USER: &str = "proxlet-user";
const PASSWORD: &str = "proxlet-password";

#[tokio::test]
async fn https_listener_forwards_http_request_with_generated_certificate() -> Result<()> {
    let certs = TestCertificates::generate()?;
    let origin = start_origin("TLS").await?;
    let proxlet = start_proxlet(
        ProxyType::Https,
        None,
        Some((certs.proxy_cert.clone(), certs.proxy_key.clone())),
    )
    .await?;

    let response = proxy_get_over_tls(proxlet.addr, origin.addr, certs.ca_cert.as_path()).await?;

    assert_response_body(&response, "TLS");
    origin.task.await??;
    Ok(())
}

#[tokio::test]
async fn chains_through_live_http_upstream_proxy() -> Result<()> {
    let origin = start_origin("HTTP").await?;
    let upstream = start_http_upstream().await?;
    let proxlet = start_proxlet(
        ProxyType::Http,
        Some(upstream_url("http", upstream.addr, USER, PASSWORD)?),
        None,
    )
    .await?;

    let response = proxy_get_plain(proxlet.addr, "localhost", origin.addr.port()).await?;

    assert_response_body(&response, "HTTP");
    origin.task.await??;
    upstream.task.await??;
    Ok(())
}

#[tokio::test]
async fn http_upstream_authentication_failure_returns_bad_gateway() -> Result<()> {
    let upstream = start_http_upstream().await?;
    let proxlet = start_proxlet(
        ProxyType::Http,
        Some(upstream_url("http", upstream.addr, USER, "wrong-password")?),
        None,
    )
    .await?;

    let response = proxy_get_plain(proxlet.addr, "localhost", 1).await?;

    assert!(response.starts_with(b"HTTP/1.1 503 Service Temporarily Unavailable\r\n"));
    upstream.task.await??;
    Ok(())
}

#[tokio::test]
async fn chains_through_live_socks5h_upstream_proxy() -> Result<()> {
    let origin = start_origin("SOCKS").await?;
    let upstream = start_socks5h_upstream().await?;
    let proxlet = start_proxlet(
        ProxyType::Http,
        Some(upstream_url("socks5h", upstream.addr, USER, PASSWORD)?),
        None,
    )
    .await?;

    let response = proxy_get_plain(proxlet.addr, "localhost", origin.addr.port()).await?;

    assert_response_body(&response, "SOCKS");
    origin.task.await??;
    upstream.task.await??;
    Ok(())
}

#[tokio::test]
async fn chains_through_live_encrypted_fakehttp_upstream_proxy() -> Result<()> {
    let origin = start_origin("FAKEHTTP").await?;
    let upstream =
        start_proxlet_with_aes_secret(ProxyType::FakeHttp, None, None, Some(PASSWORD.to_owned()))
            .await?;
    let proxlet = start_proxlet(
        ProxyType::Http,
        Some(fakehttp_upstream_url(upstream.addr, PASSWORD)?),
        None,
    )
    .await?;

    let response = proxy_get_plain(proxlet.addr, "localhost", origin.addr.port()).await?;

    assert_response_body(&response, "FAKEHTTP");
    origin.task.await??;
    Ok(())
}

#[tokio::test]
async fn socks5h_upstream_authentication_failure_returns_bad_gateway() -> Result<()> {
    let upstream = start_socks5h_upstream().await?;
    let proxlet = start_proxlet(
        ProxyType::Http,
        Some(upstream_url(
            "socks5h",
            upstream.addr,
            USER,
            "wrong-password",
        )?),
        None,
    )
    .await?;

    let response = proxy_get_plain(proxlet.addr, "localhost", 1).await?;

    assert!(response.starts_with(b"HTTP/1.1 503 Service Temporarily Unavailable\r\n"));
    upstream.task.await??;
    Ok(())
}

#[tokio::test]
async fn chains_through_live_ssh_upstream_proxy() -> Result<()> {
    let origin = start_origin("SSH").await?;
    let upstream = start_ssh_upstream(None).await?;
    let proxlet = start_proxlet(
        ProxyType::Http,
        Some(upstream_url("ssh", upstream.addr, USER, PASSWORD)?),
        None,
    )
    .await?;

    let response = proxy_get_plain(proxlet.addr, "localhost", origin.addr.port()).await?;

    assert_response_body(&response, "SSH");
    origin.task.await??;
    Ok(())
}

#[tokio::test]
async fn ssh_upstream_authentication_failure_returns_bad_gateway() -> Result<()> {
    let upstream = start_ssh_upstream(None).await?;
    let proxlet = start_proxlet(
        ProxyType::Http,
        Some(upstream_url("ssh", upstream.addr, USER, "wrong-password")?),
        None,
    )
    .await?;

    let response = proxy_get_plain(proxlet.addr, "localhost", 1).await?;

    assert!(response.starts_with(b"HTTP/1.1 503 Service Temporarily Unavailable\r\n"));
    Ok(())
}

#[tokio::test]
async fn chains_through_live_ssh_upstream_with_private_key_authentication() -> Result<()> {
    let keys = tempfile::tempdir()?;
    let (key_path, public_key) = write_test_private_key(keys.path().join("id_ed25519"), 1)?;
    let origin = start_origin("SSH-KEY").await?;
    let upstream = start_ssh_upstream(Some(public_key)).await?;
    let proxlet = start_proxlet(
        ProxyType::Http,
        Some(ssh_private_key_upstream_url(
            upstream.addr,
            USER,
            &key_path,
        )?),
        None,
    )
    .await?;

    let response = proxy_get_plain(proxlet.addr, "localhost", origin.addr.port()).await?;

    assert_response_body(&response, "SSH-KEY");
    origin.task.await??;
    Ok(())
}

#[tokio::test]
async fn chains_through_live_ssh_upstream_with_rsa_private_key_authentication() -> Result<()> {
    let keys = tempfile::tempdir()?;
    let (key_path, public_key) = write_test_rsa_private_key(keys.path().join("id_rsa"), 4)?;
    let origin = start_origin("SSH-RSA-KEY").await?;
    let upstream = start_ssh_upstream(Some(public_key)).await?;
    let proxlet = start_proxlet(
        ProxyType::Http,
        Some(ssh_private_key_upstream_url(
            upstream.addr,
            USER,
            &key_path,
        )?),
        None,
    )
    .await?;

    let response = proxy_get_plain(proxlet.addr, "localhost", origin.addr.port()).await?;

    assert_response_body(&response, "SSH-RSA-KEY");
    origin.task.await??;
    Ok(())
}

#[tokio::test]
async fn ssh_upstream_private_key_authentication_failure_returns_bad_gateway() -> Result<()> {
    let keys = tempfile::tempdir()?;
    let (_, public_key) = write_test_private_key(keys.path().join("accepted_ed25519"), 2)?;
    let (wrong_key_path, _) = write_test_private_key(keys.path().join("wrong_ed25519"), 3)?;
    let upstream = start_ssh_upstream(Some(public_key)).await?;
    let proxlet = start_proxlet(
        ProxyType::Http,
        Some(ssh_private_key_upstream_url(
            upstream.addr,
            USER,
            &wrong_key_path,
        )?),
        None,
    )
    .await?;

    let response = proxy_get_plain(proxlet.addr, "localhost", 1).await?;

    assert!(response.starts_with(b"HTTP/1.1 503 Service Temporarily Unavailable\r\n"));
    Ok(())
}

struct RunningProxlet {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for RunningProxlet {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_proxlet(
    proxy_type: ProxyType,
    upstream: Option<Url>,
    tls: Option<(PathBuf, PathBuf)>,
) -> Result<RunningProxlet> {
    start_proxlet_with_aes_secret(proxy_type, upstream, tls, None).await
}

async fn start_proxlet_with_aes_secret(
    proxy_type: ProxyType,
    upstream: Option<Url>,
    tls: Option<(PathBuf, PathBuf)>,
    aes_secret: Option<String>,
) -> Result<RunningProxlet> {
    let addr = unused_addr()?;
    let (tls_cert, tls_key) = tls
        .map(|(cert, key)| (Some(cert), Some(key)))
        .unwrap_or((None, None));
    let cli = Cli {
        daemon: false,
        allow_ip: Vec::new(),
        lhost: "127.0.0.1".to_owned(),
        lport: addr.port(),
        password: None,
        username: None,
        proxy_type,
        proxy: upstream,
        aes_secret,
        max_frame_size: 16,
        proxy_ca: None,
        tls_cert,
        tls_key,
        connect_timeout: 10,
    };
    let task = tokio::spawn(async move {
        proxlet::run(cli).await.expect("proxlet listener failed");
    });
    wait_for_tcp(addr).await?;
    Ok(RunningProxlet { addr, task })
}

struct TestCertificates {
    _dir: TempDir,
    ca_cert: PathBuf,
    proxy_cert: PathBuf,
    proxy_key: PathBuf,
}

impl TestCertificates {
    fn generate() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let status = Command::new("bash")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("create_cert_key.sh"))
            .arg("--output-dir")
            .arg(dir.path())
            .status()
            .context("could not run test certificate generator")?;
        if !status.success() {
            bail!("test certificate generator exited with {status}");
        }
        Ok(Self {
            ca_cert: dir.path().join("proxlet-ca.pem"),
            proxy_cert: dir.path().join("proxlet-cert.pem"),
            proxy_key: dir.path().join("proxlet-key.pem"),
            _dir: dir,
        })
    }
}

struct Origin {
    addr: SocketAddr,
    task: JoinHandle<Result<()>>,
}

async fn start_origin(body: &'static str) -> Result<Origin> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let header = read_header(&mut stream).await?;
        assert!(header.starts_with(b"GET /ready HTTP/1.1\r\n"));
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .await?;
        Ok(())
    });
    Ok(Origin { addr, task })
}

struct UpstreamFixture {
    addr: SocketAddr,
    task: JoinHandle<Result<()>>,
}

async fn start_http_upstream() -> Result<UpstreamFixture> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await?;
        let header = read_header(&mut client).await?;
        let header_text = std::str::from_utf8(&header)?;
        let expected = BASE64.encode(format!("{USER}:{PASSWORD}"));
        if !header_text
            .lines()
            .any(|line| line == format!("Proxy-Authorization: Basic {expected}"))
        {
            client
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await?;
            return Ok(());
        }
        let target = header_text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or_else(|| anyhow::anyhow!("CONNECT request did not include a target"))?;
        let mut remote = TcpStream::connect(target).await?;
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
        Ok(())
    });
    Ok(UpstreamFixture { addr, task })
}

async fn start_socks5h_upstream() -> Result<UpstreamFixture> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await?;
        let mut greeting = [0_u8; 2];
        client.read_exact(&mut greeting).await?;
        assert_eq!(greeting[0], 0x05);
        let mut methods = vec![0_u8; greeting[1] as usize];
        client.read_exact(&mut methods).await?;
        assert!(methods.contains(&0x02));
        client.write_all(&[0x05, 0x02]).await?;

        let version = read_u8(&mut client).await?;
        assert_eq!(version, 0x01);
        let username = read_socks_string(&mut client).await?;
        let password = read_socks_string(&mut client).await?;
        if username != USER || password != PASSWORD {
            client.write_all(&[0x01, 0x01]).await?;
            return Ok(());
        }
        client.write_all(&[0x01, 0x00]).await?;

        let mut request = [0_u8; 4];
        client.read_exact(&mut request).await?;
        assert_eq!(request, [0x05, 0x01, 0x00, 0x03]);
        let host = read_socks_string(&mut client).await?;
        assert_eq!(host, "localhost");
        let mut port = [0_u8; 2];
        client.read_exact(&mut port).await?;
        let mut remote = TcpStream::connect((host.as_str(), u16::from_be_bytes(port))).await?;
        client
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await?;
        tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
        Ok(())
    });
    Ok(UpstreamFixture { addr, task })
}

struct SshFixture {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for SshFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_ssh_upstream(authorized_key: Option<PublicKey>) -> Result<SshFixture> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let config = Arc::new(russh::server::Config {
            auth_rejection_time: Duration::from_millis(1),
            auth_rejection_time_initial: Some(Duration::from_millis(1)),
            keys: vec![
                PrivateKey::random(&mut DeterministicRng::new(), Algorithm::Ed25519)
                    .expect("generated SSH host key"),
            ],
            ..Default::default()
        });
        let mut server = SshProxyServer { authorized_key };
        server
            .run_on_socket(config, &listener)
            .await
            .expect("SSH fixture failed");
    });
    Ok(SshFixture { addr, task })
}

struct DeterministicRng(u64);

impl DeterministicRng {
    fn new() -> Self {
        Self::with_seed(0)
    }

    fn with_seed(seed: u64) -> Self {
        Self(0x9e37_79b9_7f4a_7c15 ^ seed)
    }
}

impl rand_core::TryRng for DeterministicRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 ^= self.0 << 7;
        self.0 ^= self.0 >> 9;
        self.0 ^= self.0 << 8;
        Ok(self.0)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(std::mem::size_of::<u64>()) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for DeterministicRng {}

#[derive(Clone)]
struct SshProxyServer {
    authorized_key: Option<PublicKey>,
}

impl Server for SshProxyServer {
    type Handler = Self;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        self.clone()
    }
}

impl Handler for SshProxyServer {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == USER && password == PASSWORD {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        if user == USER
            && self
                .authorized_key
                .as_ref()
                .is_some_and(|expected| expected == public_key)
        {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _: &str,
        _: u32,
        _: &mut Session,
    ) -> Result<bool, Self::Error> {
        let host = host_to_connect.to_owned();
        let port = u16::try_from(port_to_connect)?;
        tokio::spawn(async move {
            let mut channel = channel.into_stream();
            let mut remote = TcpStream::connect((host.as_str(), port))
                .await
                .expect("SSH direct-tcpip target connection");
            tokio::io::copy_bidirectional(&mut channel, &mut remote)
                .await
                .expect("SSH direct-tcpip relay");
        });
        Ok(true)
    }
}

async fn proxy_get_plain(proxy: SocketAddr, host: &str, port: u16) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect(proxy).await?;
    write_proxy_get(&mut stream, host, port).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

async fn proxy_get_over_tls(
    proxy: SocketAddr,
    origin: SocketAddr,
    ca_cert: &Path,
) -> Result<Vec<u8>> {
    let mut roots = RootCertStore::empty();
    let mut reader = std::io::BufReader::new(std::fs::File::open(ca_cert)?);
    for cert in rustls_pemfile::certs(&mut reader) {
        roots.add(cert?)?;
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let stream = TcpStream::connect(proxy).await?;
    let server_name = ServerName::try_from("localhost")?;
    let mut stream = TlsConnector::from(Arc::new(config))
        .connect(server_name, stream)
        .await?;
    write_proxy_get(&mut stream, "localhost", origin.port()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

async fn write_proxy_get<S>(stream: &mut S, host: &str, port: u16) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    stream
        .write_all(
            format!("GET http://{host}:{port}/ready HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    stream.shutdown().await?;
    Ok(())
}

async fn read_header(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = Vec::with_capacity(256);
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await?;
        header.push(byte[0]);
    }
    Ok(header)
}

async fn read_socks_string(stream: &mut TcpStream) -> Result<String> {
    let length = read_u8(stream).await? as usize;
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes).await?;
    Ok(String::from_utf8(bytes)?)
}

async fn read_u8(stream: &mut TcpStream) -> Result<u8> {
    let mut byte = [0_u8; 1];
    stream.read_exact(&mut byte).await?;
    Ok(byte[0])
}

fn assert_response_body(response: &[u8], body: &str) {
    let text = std::str::from_utf8(response).expect("response is UTF-8");
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    assert!(text.ends_with(body), "{text}");
}

fn upstream_url(scheme: &str, addr: SocketAddr, username: &str, password: &str) -> Result<Url> {
    Ok(Url::parse(&format!(
        "{scheme}://{username}:{password}@127.0.0.1:{}",
        addr.port()
    ))?)
}

fn fakehttp_upstream_url(addr: SocketAddr, aes_secret: &str) -> Result<Url> {
    Ok(Url::parse(&format!(
        "fakehttp://{aes_secret}@127.0.0.1:{}",
        addr.port()
    ))?)
}

fn ssh_private_key_upstream_url(addr: SocketAddr, username: &str, key_path: &Path) -> Result<Url> {
    let mut url = Url::parse(&format!("ssh://{username}@127.0.0.1:{}", addr.port()))?;
    url.query_pairs_mut().append_pair(
        "key",
        key_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("test key path is not UTF-8"))?,
    );
    Ok(url)
}

fn write_test_private_key(path: PathBuf, seed: u64) -> Result<(PathBuf, PublicKey)> {
    let key = PrivateKey::random(&mut DeterministicRng::with_seed(seed), Algorithm::Ed25519)?;
    let public_key = key.public_key().clone();
    key.write_openssh_file(&path, ssh_key::LineEnding::LF)?;
    Ok((path, public_key))
}

fn write_test_rsa_private_key(path: PathBuf, seed: u64) -> Result<(PathBuf, PublicKey)> {
    let key = PrivateKey::from(ssh_key::private::RsaKeypair::random(
        &mut DeterministicRng::with_seed(seed),
        2048,
    )?);
    let public_key = key.public_key().clone();
    key.write_openssh_file(&path, ssh_key::LineEnding::LF)?;
    Ok((path, public_key))
}

fn unused_addr() -> Result<SocketAddr> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?)
}

async fn wait_for_tcp(addr: SocketAddr) -> Result<()> {
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    bail!("listener did not start on {addr}")
}
