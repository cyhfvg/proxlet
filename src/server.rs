use std::fs::File;
use std::io::{self, BufReader, Cursor};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;

use crate::cli::{Cli, Config, ProxyType};
use crate::connector::Connector;
use crate::{fakehttp, http, socks};

pub async fn run(cli: Cli) -> Result<()> {
    let config = Arc::new(cli.into_config().await?);
    let connector = Arc::new(Connector::new(
        config.upstream.clone(),
        config.upstream_ca.as_deref(),
    )?);
    let tls = load_tls(&config)?;
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("could not bind {}", config.listen))?;
    println!(
        "proxlet listening on {} as {} proxy",
        listener.local_addr()?,
        config.proxy_type
    );
    if config.proxy_type == ProxyType::Mixed && tls.is_none() {
        println!("proxlet: mixed mode HTTPS listener is disabled until TLS files are provided");
    }

    loop {
        let (stream, peer) = listener.accept().await?;
        if !config.allowed_ips.is_empty()
            && !config
                .allowed_ips
                .iter()
                .any(|allowed| allowed.contains(&peer.ip()))
        {
            eprintln!("proxlet: rejected connection from {}", peer.ip());
            continue;
        }
        let config = config.clone();
        let connector = connector.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_client(stream, config, connector, tls).await {
                eprintln!("proxlet: connection from {} failed: {error:#}", peer.ip());
            }
        });
    }
}

async fn serve_client(
    stream: TcpStream,
    config: Arc<Config>,
    connector: Arc<Connector>,
    tls: Option<TlsAcceptor>,
) -> Result<()> {
    match config.proxy_type {
        ProxyType::Http => {
            http::serve(Box::new(stream), &[], connector, config.auth.as_ref()).await
        }
        ProxyType::Https => {
            let tls = tls.ok_or_else(|| anyhow::anyhow!("TLS listener is not configured"))?;
            let stream = tls.accept(stream).await?;
            http::serve(Box::new(stream), &[], connector, config.auth.as_ref()).await
        }
        ProxyType::Socks5 | ProxyType::Socks5h => {
            socks::serve(Box::new(stream), None, connector, config.auth.as_ref()).await
        }
        ProxyType::Mixed => serve_mixed(stream, connector, config.auth.as_ref(), tls).await,
        ProxyType::FakeHttp => {
            fakehttp::serve(Box::new(stream), connector, config.aes_secret.as_deref()).await
        }
    }
}

async fn serve_mixed(
    mut stream: TcpStream,
    connector: Arc<Connector>,
    auth: Option<&crate::cli::Auth>,
    tls: Option<TlsAcceptor>,
) -> Result<()> {
    let mut first = [0_u8; 1];
    stream.read_exact(&mut first).await?;
    match first[0] {
        0x05 => socks::serve(Box::new(stream), Some(0x05), connector, auth).await,
        0x16 => {
            let tls = tls.ok_or_else(|| {
                anyhow::anyhow!("received a TLS client connection but TLS files are not configured")
            })?;
            let stream = tls
                .accept(PrefixStream::new(first.to_vec(), stream))
                .await?;
            http::serve(Box::new(stream), &[], connector, auth).await
        }
        byte => http::serve(Box::new(stream), &[byte], connector, auth).await,
    }
}

fn load_tls(config: &Config) -> Result<Option<TlsAcceptor>> {
    let (Some(cert_path), Some(key_path)) = (&config.tls_cert, &config.tls_key) else {
        return Ok(None);
    };
    let mut cert_reader = BufReader::new(
        File::open(cert_path).with_context(|| format!("could not open {}", cert_path.display()))?,
    );
    let certs = rustls_pemfile::certs(&mut cert_reader).collect::<io::Result<Vec<_>>>()?;
    if certs.is_empty() {
        bail!("TLS certificate file contains no certificates")
    }
    let mut key_reader = BufReader::new(
        File::open(key_path).with_context(|| format!("could not open {}", key_path.display()))?,
    );
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("TLS key file contains no private key"))?;
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Some(TlsAcceptor::from(Arc::new(server))))
}

struct PrefixStream {
    prefix: Cursor<Vec<u8>>,
    inner: TcpStream,
}

impl PrefixStream {
    fn new(prefix: Vec<u8>, inner: TcpStream) -> Self {
        Self {
            prefix: Cursor::new(prefix),
            inner,
        }
    }
}

impl AsyncRead for PrefixStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let position = self.prefix.position() as usize;
        let prefix = self.prefix.get_ref();
        if position < prefix.len() {
            let count = buffer.remaining().min(prefix.len() - position);
            buffer.put_slice(&prefix[position..position + count]);
            self.prefix.set_position((position + count) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for PrefixStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}
