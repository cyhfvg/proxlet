//! Security behavior of the fakehttp handshake against a live listener.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, Result};
use proxlet::connector::{BoxStream, Connector, Target};
use proxlet::fakehttp;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Stream that records bytes accepted by `poll_write`.
///
/// # Parameters
///
/// * `inner` - Downstream byte stream.
/// * `written` - Shared buffer of bytes the inner stream accepted.
struct RecordingStream {
    inner: BoxStream,
    written: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for RecordingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for RecordingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(context, bytes) {
            Poll::Ready(Ok(written)) => {
                self.written
                    .lock()
                    .expect("handshake record lock")
                    .extend_from_slice(&bytes[..written]);
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[tokio::test]
async fn wrong_secret_handshake_is_rejected_without_dialing_the_target() -> Result<()> {
    let (origin_addr, dialed, origin_task) = watched_origin().await?;
    let endpoint = Target::new("127.0.0.1", 1);
    let target = Target::new("127.0.0.1", origin_addr.port());
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(fakehttp::serve(
        Box::new(server_side),
        Arc::new(Connector::new(None, None)?),
        Some("server-secret"),
        fakehttp::DEFAULT_MAX_FRAME_SIZE,
    ));
    let connect_result = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        fakehttp::connect(
            Box::new(client_side),
            &endpoint,
            &target,
            Some("client-secret"),
            fakehttp::DEFAULT_MAX_FRAME_SIZE,
            Duration::from_secs(10),
        ),
    )
    .await
    .context("wrong secret handshake hung instead of failing")?;
    assert!(
        connect_result.is_err(),
        "wrong secret must be rejected before a tunnel is opened"
    );
    let serve_result = tokio::time::timeout(HANDSHAKE_TIMEOUT, server_task)
        .await
        .context("fakehttp serve hung after a wrong secret")?;
    assert!(
        serve_result?.is_err(),
        "serve must fail closed after writing the camouflage response"
    );
    assert!(
        !dialed.load(Ordering::SeqCst),
        "server must not dial the target before the hello frame authenticates"
    );
    origin_task.abort();
    Ok(())
}

#[tokio::test]
async fn encryption_mismatch_names_the_side_missing_a_secret() -> Result<()> {
    let listener_missing = policy_mismatch(None, Some("client-secret")).await?;
    assert!(
        listener_missing
            .server
            .contains("listener has no AES secret"),
        "{}",
        listener_missing.server
    );
    assert!(
        listener_missing
            .client
            .contains("client requested encryption"),
        "{}",
        listener_missing.client
    );
    assert!(!listener_missing.server.contains("client-secret"));
    assert!(!listener_missing.client.contains("client-secret"));

    let client_missing = policy_mismatch(Some("server-secret"), None).await?;
    assert!(
        client_missing
            .server
            .contains("client did not request encryption"),
        "{}",
        client_missing.server
    );
    assert!(
        client_missing.client.contains("client has no AES secret"),
        "{}",
        client_missing.client
    );
    assert!(!client_missing.server.contains("server-secret"));
    assert!(!client_missing.client.contains("server-secret"));
    Ok(())
}

async fn policy_mismatch(
    listener_secret: Option<&'static str>,
    client_secret: Option<&'static str>,
) -> Result<PolicyErrors> {
    let endpoint = Target::new("127.0.0.1", 1);
    let target = Target::new("127.0.0.1", 1);
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(fakehttp::serve(
        Box::new(server_side),
        Arc::new(Connector::new(None, None)?),
        listener_secret,
        fakehttp::DEFAULT_MAX_FRAME_SIZE,
    ));
    let client_result = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        fakehttp::connect(
            Box::new(client_side),
            &endpoint,
            &target,
            client_secret,
            fakehttp::DEFAULT_MAX_FRAME_SIZE,
            Duration::from_secs(10),
        ),
    )
    .await
    .context("policy mismatch handshake hung")?;
    let server_result = tokio::time::timeout(HANDSHAKE_TIMEOUT, server_task)
        .await
        .context("policy mismatch serve hung")??;
    let client = match client_result {
        Err(error) => error.to_string(),
        Ok(_) => anyhow::bail!("client mismatch was accepted"),
    };
    Ok(PolicyErrors {
        server: server_result.expect_err("server mismatch").to_string(),
        client,
    })
}

struct PolicyErrors {
    server: String,
    client: String,
}

#[tokio::test]
async fn replayed_handshake_is_rejected() -> Result<()> {
    let (origin_addr, accepts, origin_task) = counting_origin().await?;
    let endpoint = Target::new("127.0.0.1", 1);
    let target = Target::new("127.0.0.1", origin_addr.port());
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let connector = Arc::new(Connector::new(None, None)?);
    let server_task = tokio::spawn(fakehttp::serve(
        Box::new(server_side),
        Arc::clone(&connector),
        Some("shared-secret"),
        fakehttp::DEFAULT_MAX_FRAME_SIZE,
    ));
    let written = Arc::new(Mutex::new(Vec::new()));
    let recording = RecordingStream {
        inner: Box::new(client_side),
        written: Arc::clone(&written),
    };
    let mut first = fakehttp::connect(
        Box::new(recording),
        &endpoint,
        &target,
        Some("shared-secret"),
        fakehttp::DEFAULT_MAX_FRAME_SIZE,
        Duration::from_secs(10),
    )
    .await
    .context("first handshake")?;
    let captured = written.lock().expect("handshake record lock").clone();
    assert!(
        captured.windows(4).any(|window| window == b"\r\n\r\n"),
        "captured handshake must include the request header"
    );
    assert!(
        captured.len() > b"POST /api/v1/stream HTTP/1.1\r\n".len() + 8,
        "captured handshake must include the hello chunk, not only headers"
    );

    first.write_all(b"ping").await?;
    first.shutdown().await?;
    let mut echoed = Vec::new();
    first.read_to_end(&mut echoed).await?;
    assert_eq!(echoed, b"ping");
    server_task.await??;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "the first handshake must dial the target exactly once"
    );

    let (replay_client, replay_server) = tokio::io::duplex(64 * 1024);
    let replay_task = tokio::spawn(fakehttp::serve(
        Box::new(replay_server),
        connector,
        Some("shared-secret"),
        fakehttp::DEFAULT_MAX_FRAME_SIZE,
    ));
    let mut replay_client = replay_client;
    replay_client.write_all(&captured).await?;
    replay_client.flush().await?;
    let mut response = Vec::new();
    tokio::time::timeout(HANDSHAKE_TIMEOUT, replay_client.read_to_end(&mut response))
        .await
        .context("replayed handshake hung instead of being rejected")??;
    let reply = String::from_utf8_lossy(&response);
    assert!(
        reply.starts_with("HTTP/1.1 404"),
        "replayed handshake must look like a missing resource, got {reply}"
    );
    let replay_result = tokio::time::timeout(HANDSHAKE_TIMEOUT, replay_task)
        .await
        .context("fakehttp serve hung after a replayed handshake")?;
    assert!(
        replay_result?.is_err(),
        "serve must reject a replayed client nonce"
    );
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "a replayed handshake must not dial the captured target again"
    );
    origin_task.abort();
    Ok(())
}

#[tokio::test]
async fn plaintext_handshake_without_crypto_policy_tunnels_without_salt() -> Result<()> {
    let (origin_addr, origin_task) = echo_origin().await?;
    let endpoint = Target::new("127.0.0.1", 1);
    let target = Target::new("127.0.0.1", origin_addr.port());
    let (client_side, server_side) = tokio::io::duplex(8 * 1024);
    let server_task = tokio::spawn(fakehttp::serve(
        Box::new(server_side),
        Arc::new(Connector::new(None, None)?),
        None,
        fakehttp::DEFAULT_MAX_FRAME_SIZE,
    ));
    let mut client = fakehttp::connect(
        Box::new(client_side),
        &endpoint,
        &target,
        None,
        fakehttp::DEFAULT_MAX_FRAME_SIZE,
        Duration::from_secs(10),
    )
    .await
    .context("plaintext handshake")?;

    client.write_all(b"plain").await?;
    client.shutdown().await?;
    let mut echoed = Vec::new();
    client.read_to_end(&mut echoed).await?;
    assert_eq!(echoed, b"plain");
    server_task.await??;
    origin_task.await??;
    Ok(())
}

/// Bind an origin that records whether `accept` succeeded.
///
/// # Parameters
///
/// This function takes no parameters.
///
/// # Returns
///
/// Returns the bound address, a flag set only after `accept` succeeds, and the
/// listener task.
///
/// # Errors
///
/// Returns an error when binding the listener fails.
///
/// # Examples
///
/// ```ignore
/// let (addr, dialed, task) = watched_origin().await?;
/// ```
async fn watched_origin() -> Result<(SocketAddr, Arc<AtomicBool>, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let dialed = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&dialed);
    let task = tokio::spawn(async move {
        if listener.accept().await.is_ok() {
            flag.store(true, Ordering::SeqCst);
        }
    });
    Ok((addr, dialed, task))
}

/// Bind an origin that counts accepted connections and echoes each one.
///
/// # Parameters
///
/// This function takes no parameters.
///
/// # Returns
///
/// Returns the bound address, the accept counter, and the listener task.
///
/// # Errors
///
/// Returns an error when binding the listener fails.
///
/// # Examples
///
/// ```ignore
/// let (addr, accepts, task) = counting_origin().await?;
/// ```
async fn counting_origin() -> Result<(SocketAddr, Arc<AtomicUsize>, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let accepts = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&accepts);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            seen.fetch_add(1, Ordering::SeqCst);
            let mut buffer = Vec::new();
            if stream.read_to_end(&mut buffer).await.is_err() {
                continue;
            }
            let _ = stream.write_all(&buffer).await;
        }
    });
    Ok((addr, accepts, task))
}

/// Bind a one-shot origin that echoes bytes until the client closes.
///
/// # Parameters
///
/// This function takes no parameters.
///
/// # Returns
///
/// Returns the bound address and the echo task.
///
/// # Errors
///
/// Returns an error when binding, accepting, or echoing fails.
///
/// # Examples
///
/// ```ignore
/// let (addr, task) = echo_origin().await?;
/// ```
async fn echo_origin() -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buffer = Vec::new();
        stream.read_to_end(&mut buffer).await?;
        stream.write_all(&buffer).await?;
        Ok(())
    });
    Ok((addr, task))
}
