//! Server runtime for accepting clients and dispatching proxy protocols.
//!
//! This module owns listener setup, client allow-list checks, TLS listener
//! loading, mixed-mode protocol detection, and per-connection task spawning.

use std::fs::File;
use std::io::{self, BufReader, Cursor, Write};
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

/// Run the proxlet server until the listening socket is closed.
///
/// # Parameters
///
/// * `cli` - Parsed command-line options.
///
/// # Returns
///
/// This function normally runs forever. Transient `accept` errors are logged
/// and retried. It returns after listener setup fails or the listening socket
/// is closed.
///
/// # Errors
///
/// TLS loading, listen binding, local address lookup, daemon readiness
/// reporting, or a closed listening socket fails the accept loop.
pub async fn run(cli: Cli) -> Result<()> {
    for flag in cli.visible_secret_flags() {
        log_line(format!(
            "proxlet: {flag} remains visible in process arguments; prefer a mode 0600 file"
        ));
    }
    let config = Arc::new(cli.into_config().await?);
    let connector = Arc::new(
        Connector::with_fakehttp_max_frame_size(
            config.upstream.clone(),
            config.upstream_ca.as_deref(),
            config.max_frame_size,
        )?
        .with_connect_timeout(config.connect_timeout),
    );
    let tls = load_tls(&config)?;
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("could not bind {}", config.listen))?;
    let local = listener
        .local_addr()
        .context("could not read listen address")?;
    log_line(format!(
        "proxlet listening on {local} as {} proxy",
        config.proxy_type
    ));
    log_line(if config.auth.is_some() {
        "proxlet: authentication enabled"
    } else {
        "proxlet: authentication disabled"
    });
    if config.proxy_type == ProxyType::FakeHttp && config.aes_secret.is_none() {
        log_line(crate::secret::PLAINTEXT_LISTENER);
    }
    if config
        .upstream
        .as_ref()
        .is_some_and(crate::secret::url_is_plaintext_fakehttp)
    {
        log_line(crate::secret::PLAINTEXT_UPSTREAM);
    }
    if config.proxy_type == ProxyType::Mixed && tls.is_none() {
        log_line("proxlet: mixed mode HTTPS listener is disabled until TLS files are provided");
    }
    crate::daemon::report_ready(local)?;

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) if accept_error_is_fatal(&error) => {
                let error = anyhow::Error::from(error).context("listening socket is closed");
                log_line(format!("proxlet: {error:#}"));
                return Err(error);
            }
            Err(error) => {
                // EMFILE, ENFILE, ECONNABORTED, ENOBUFS 这类错误不能结束进程.
                log_line(format!("proxlet: accept failed: {error:#}; retrying"));
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        // The allow-list is checked before spawning so rejected clients do not
        // consume per-connection task resources.
        if !config.allowed_ips.is_empty()
            && !config
                .allowed_ips
                .iter()
                .any(|allowed| allowed.contains(&peer.ip()))
        {
            crate::access::record(peer.ip(), "-", None, "rejected");
            continue;
        }
        let config = config.clone();
        let connector = connector.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_client(stream, peer.ip(), config, connector, tls).await {
                log_line(format!(
                    "proxlet: connection from {} failed: {error:#}",
                    peer.ip()
                ));
            }
        });
    }
}

/// Serve one accepted TCP client according to configured proxy type.
///
/// # Parameters
///
/// * `stream` - Accepted TCP client stream.
/// * `peer` - Client IP recorded in the access log.
/// * `config` - Shared runtime configuration.
/// * `connector` - Shared upstream connector.
/// * `tls` - Optional TLS acceptor for HTTPS listener or mixed TLS detection.
///
/// # Returns
///
/// Returns `Ok(())` when the client connection finishes successfully.
///
/// # Errors
///
/// Returns an error from protocol handling, TLS acceptance, missing TLS
/// configuration, or traffic relay.
async fn serve_client(
    stream: TcpStream,
    peer: std::net::IpAddr,
    config: Arc<Config>,
    connector: Arc<Connector>,
    tls: Option<TlsAcceptor>,
) -> Result<()> {
    crate::connector::enable_tcp_nodelay(&stream)?;
    match config.proxy_type {
        ProxyType::Http => {
            http::serve(
                Box::new(stream),
                &[],
                connector,
                config.auth.as_ref(),
                peer,
                "http",
            )
            .await
        }
        ProxyType::Https => {
            let tls = tls.ok_or_else(|| anyhow::anyhow!("TLS listener is not configured"))?;
            let stream = crate::connector::with_timeout(
                connector.connect_timeout(),
                "TLS handshake",
                tls.accept(stream),
            )
            .await?;
            http::serve(
                Box::new(stream),
                &[],
                connector,
                config.auth.as_ref(),
                peer,
                "https",
            )
            .await
        }
        ProxyType::Socks5 | ProxyType::Socks5h => {
            socks::serve(
                Box::new(stream),
                None,
                connector,
                config.auth.as_ref(),
                peer,
                "socks5",
            )
            .await
        }
        ProxyType::Mixed => serve_mixed(stream, peer, connector, config.auth.as_ref(), tls).await,
        ProxyType::FakeHttp => {
            let result = fakehttp::serve(
                Box::new(stream),
                connector,
                config.aes_secret.as_deref(),
                config.max_frame_size,
            )
            .await;
            let outcome = if result.is_ok() { "ok" } else { "error" };
            crate::access::record(peer, "fakehttp", None, outcome);
            result
        }
    }
}

/// Detect the client protocol for mixed listener mode.
///
/// # Parameters
///
/// * `stream` - Accepted TCP stream.
/// * `peer` - Client IP recorded in the access log.
/// * `auth` - Optional listener authentication credentials.
/// * `tls` - Optional TLS acceptor used for HTTPS-looking clients.
///
/// # Returns
///
/// Returns `Ok(())` when the selected protocol handler completes.
///
/// # Errors
///
/// Returns an error when the first byte cannot be read, TLS is required but not
/// configured, TLS acceptance fails, or the selected protocol handler fails.
async fn serve_mixed(
    mut stream: TcpStream,
    peer: std::net::IpAddr,
    connector: Arc<Connector>,
    auth: Option<&crate::cli::Auth>,
    tls: Option<TlsAcceptor>,
) -> Result<()> {
    let mut first = [0_u8; 1];
    crate::connector::with_timeout(
        connector.connect_timeout(),
        "mixed protocol detection",
        stream.read_exact(&mut first),
    )
    .await?;
    // Mixed mode uses the first byte only for dispatch, then replays it through
    // PrefixStream for protocols that still need to consume it.
    match first[0] {
        0x05 => {
            socks::serve(
                Box::new(stream),
                Some(0x05),
                connector,
                auth,
                peer,
                "socks5",
            )
            .await
        }
        0x16 => {
            let tls = tls.ok_or_else(|| {
                anyhow::anyhow!("received a TLS client connection but TLS files are not configured")
            })?;
            let stream = crate::connector::with_timeout(
                connector.connect_timeout(),
                "TLS handshake",
                tls.accept(PrefixStream::new(first.to_vec(), stream)),
            )
            .await?;
            http::serve(Box::new(stream), &[], connector, auth, peer, "https").await
        }
        byte => http::serve(Box::new(stream), &[byte], connector, auth, peer, "http").await,
    }
}

/// Load TLS listener configuration from PEM certificate and key files.
///
/// # Parameters
///
/// * `config` - Runtime configuration containing optional TLS file paths.
///
/// # Returns
///
/// Returns a TLS acceptor when both TLS files are configured, otherwise `None`.
///
/// # Errors
///
/// Returns an error when files cannot be opened, PEM parsing fails, the
/// certificate list is empty, no private key is present, or rustls rejects the
/// certificate/key pair.
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

/// Stream wrapper that replays bytes already consumed during protocol detection.
struct PrefixStream {
    prefix: Cursor<Vec<u8>>,
    inner: TcpStream,
}

impl PrefixStream {
    /// Create a stream that yields `prefix` before reading from `inner`.
    ///
    /// # Parameters
    ///
    /// * `prefix` - Bytes to replay first.
    /// * `inner` - TCP stream to read after the prefix.
    ///
    /// # Returns
    ///
    /// Returns a new [`PrefixStream`].
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    fn new(prefix: Vec<u8>, inner: TcpStream) -> Self {
        Self {
            prefix: Cursor::new(prefix),
            inner,
        }
    }
}

impl AsyncRead for PrefixStream {
    /// Poll bytes from the replay prefix, then the inner TCP stream.
    ///
    /// # Parameters
    ///
    /// * `self` - Pinned prefix stream.
    /// * `context` - Async task context.
    /// * `buffer` - Destination read buffer.
    ///
    /// # Returns
    ///
    /// Returns `Ready(Ok(()))` when bytes or EOF are available, and `Pending`
    /// when the inner stream is not ready.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from the inner stream.
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
    /// Poll to write bytes to the inner stream.
    ///
    /// # Parameters
    ///
    /// * `self` - Pinned prefix stream.
    /// * `context` - Async task context.
    /// * `bytes` - Bytes to write.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from the inner stream.
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    /// Poll to flush the inner stream.
    ///
    /// # Parameters
    ///
    /// * `self` - Pinned prefix stream.
    /// * `context` - Async task context.
    ///
    /// # Returns
    ///
    /// Returns `Ready(Ok(()))` once flushing completes.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from the inner stream.
    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    /// Poll to shut down the inner stream.
    ///
    /// # Parameters
    ///
    /// * `self` - Pinned prefix stream.
    /// * `context` - Async task context.
    ///
    /// # Returns
    ///
    /// Returns `Ready(Ok(()))` once shutdown completes.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from the inner stream.
    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

const ACCEPT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);

/// Decide whether an `accept` error means the listening socket is closed.
///
/// # Parameters
///
/// * `error` - Error returned by `TcpListener::accept`.
///
/// # Returns
///
/// Returns `true` when the listener can no longer accept connections. Resource
/// and per-connection errors, including `EMFILE`, `ENFILE`, `ECONNABORTED`,
/// and `ENOBUFS`, return `false`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let error = std::io::Error::from_raw_os_error(libc::EMFILE);
/// assert!(!accept_error_is_fatal(&error));
/// ```
fn accept_error_is_fatal(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
    ) {
        return true;
    }
    error.raw_os_error().is_some_and(listener_errno_is_fatal)
}
/// Write one operational line and flush it.
///
/// # Parameters
///
/// * `message` - Line to write. A trailing newline is added.
///
/// # Returns
///
/// This function does not return a value.
///
/// # Errors
///
/// Write failures are ignored. Daemon mode must not die because the log file
/// cannot accept another line.
///
/// # Examples
///
/// ```ignore
/// log_line("proxlet listening on 127.0.0.1:1080 as http proxy");
/// ```
fn log_line(message: impl std::fmt::Display) {
    // daemon 子进程的 stdout 是日志文件或 /dev/null. stderr 只留给父进程状态行.
    println!("{message}");
    let _ = io::stdout().flush();
}

#[cfg(unix)]
fn listener_errno_is_fatal(code: i32) -> bool {
    code == libc::EBADF
        || code == libc::EINVAL
        || code == libc::ENOTSOCK
        || code == libc::EOPNOTSUPP
}

#[cfg(windows)]
fn listener_errno_is_fatal(code: i32) -> bool {
    // accept 返回 Winsock 错误号, 不是 libc 的 CRT errno.
    const WSAEBADF: i32 = 10009;
    const WSAEINVAL: i32 = 10022;
    const WSAENOTSOCK: i32 = 10038;
    const WSAEOPNOTSUPP: i32 = 10045;
    const ERROR_INVALID_HANDLE: i32 = 6;
    matches!(
        code,
        WSAEBADF | WSAEINVAL | WSAENOTSOCK | WSAEOPNOTSUPP | ERROR_INVALID_HANDLE
    )
}

#[cfg(not(any(unix, windows)))]
fn listener_errno_is_fatal(_code: i32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_only_accept_errors_follow_listener_state() {
        assert!(!accept_error_is_fatal(&io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "aborted",
        )));

        assert!(accept_error_is_fatal(&io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket is not listening",
        )));
        assert!(accept_error_is_fatal(&io::Error::new(
            io::ErrorKind::Unsupported,
            "socket does not support accept",
        )));
    }

    #[cfg(unix)]
    #[test]
    fn unix_accept_errnos_keep_the_listener_up_unless_it_is_closed() {
        for code in [
            libc::EMFILE,
            libc::ENFILE,
            libc::ECONNABORTED,
            libc::ENOBUFS,
            libc::ENOMEM,
            libc::EINTR,
        ] {
            let error = io::Error::from_raw_os_error(code);
            assert!(!accept_error_is_fatal(&error), "{code}");
        }
        for code in [libc::EBADF, libc::EINVAL, libc::ENOTSOCK, libc::EOPNOTSUPP] {
            let error = io::Error::from_raw_os_error(code);
            assert!(accept_error_is_fatal(&error), "{code}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_accept_errnos_keep_the_listener_up_unless_it_is_closed() {
        for code in [10024_i32, 10053, 10055] {
            let error = io::Error::from_raw_os_error(code);
            assert!(!accept_error_is_fatal(&error), "{code}");
        }
        for code in [6_i32, 10009, 10022, 10038, 10045] {
            let error = io::Error::from_raw_os_error(code);
            assert!(accept_error_is_fatal(&error), "{code}");
        }
    }
}
