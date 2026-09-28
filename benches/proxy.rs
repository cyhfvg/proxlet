//! End-to-end proxy benchmarks for proxlet protocol paths.
//!
//! The benchmarks exercise the public protocol handlers over in-memory duplex
//! streams and loopback origin listeners, plus a bulk copy through the
//! production relay.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use proxlet::connector::{Connector, Target};
use proxlet::{fakehttp, http, socks};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

const FAKEHTTP_SECRET: &str = "bench-secret";

/// Register proxlet protocol round-trip benchmarks.
///
/// # Parameters
///
/// * `criterion` - Criterion benchmark coordinator.
///
/// # Returns
///
/// This function returns `()`.
///
/// # Errors
///
/// Benchmark registration does not return errors. Individual iterations panic
/// if the async benchmark operation fails.
fn proxy_benches(criterion: &mut Criterion) {
    let runtime = Runtime::new().expect("Tokio runtime");
    let mut group = criterion.benchmark_group("proxy_round_trip");

    group.bench_function("http_forward_proxy", |bencher| {
        bencher.to_async(&runtime).iter(|| async {
            let response = http_round_trip().await.expect("HTTP proxy round trip");
            black_box(response);
        });
    });

    group.bench_function("socks5_proxy", |bencher| {
        bencher.to_async(&runtime).iter(|| async {
            let response = socks5_round_trip().await.expect("SOCKS5 proxy round trip");
            black_box(response);
        });
    });

    group.bench_function("fakehttp_encrypted_proxy", |bencher| {
        bencher.to_async(&runtime).iter(|| async {
            let response = fakehttp_encrypted_round_trip()
                .await
                .expect("fakehttp encrypted round trip");
            black_box(response);
        });
    });
    group.finish();

    let mut bulk = criterion.benchmark_group("relay_bulk");
    bulk.throughput(criterion::Throughput::Bytes((RELAY_BULK_BYTES * 2) as u64));
    let payload = Arc::new(vec![0x5a_u8; RELAY_BULK_BYTES]);
    bulk.bench_function("tcp_256kib_each_way", |bencher| {
        let payload = Arc::clone(&payload);
        bencher.to_async(&runtime).iter(|| {
            let payload = Arc::clone(&payload);
            async move {
                let copied = relay_bulk_copy(payload).await.expect("bulk relay");
                black_box(copied);
            }
        });
    });
    bulk.finish();
}

/// Benchmark one HTTP forward-proxy request and response.
///
/// # Parameters
///
/// This function takes no parameters.
///
/// # Returns
///
/// Returns the full HTTP response bytes received by the proxy client.
///
/// # Errors
///
/// Returns an error when listener setup, proxy handling, request/response I/O,
/// or spawned task completion fails.
async fn http_round_trip() -> Result<Vec<u8>> {
    let (origin_addr, origin_task) = start_http_origin(b"OK").await?;
    let (mut caller, proxy_client) = tokio::io::duplex(64 * 1024);
    let connector = Arc::new(Connector::new(None, None)?);
    let proxy_task = tokio::spawn(async move {
        http::serve(
            Box::new(proxy_client),
            &[],
            connector,
            None,
            std::net::Ipv4Addr::LOCALHOST.into(),
            "http",
        )
        .await
    });

    caller
        .write_all(
            format!("GET http://{origin_addr}/bench HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    caller.shutdown().await?;

    let mut response = Vec::new();
    caller.read_to_end(&mut response).await?;
    origin_task.await??;
    proxy_task.await??;
    Ok(response)
}

/// Benchmark one SOCKS5 CONNECT tunnel round trip.
///
/// # Parameters
///
/// This function takes no parameters.
///
/// # Returns
///
/// Returns bytes received from the origin through the SOCKS5 tunnel.
///
/// # Errors
///
/// Returns an error when listener setup, SOCKS5 negotiation, payload I/O, or
/// spawned task completion fails.
async fn socks5_round_trip() -> Result<Vec<u8>> {
    let (origin_addr, origin_task) = start_echo_origin(b"world").await?;
    let (mut caller, proxy_client) = tokio::io::duplex(64 * 1024);
    let connector = Arc::new(Connector::new(None, None)?);
    let proxy_task = tokio::spawn(async move {
        socks::serve(
            Box::new(proxy_client),
            None,
            connector,
            None,
            std::net::Ipv4Addr::LOCALHOST.into(),
            "socks5",
        )
        .await
    });

    caller.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0_u8; 2];
    caller.read_exact(&mut method).await?;

    let mut connect = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    connect.extend_from_slice(&origin_addr.port().to_be_bytes());
    caller.write_all(&connect).await?;
    let mut reply = [0_u8; 10];
    caller.read_exact(&mut reply).await?;

    caller.write_all(b"hello").await?;
    caller.shutdown().await?;
    let mut response = Vec::new();
    caller.read_to_end(&mut response).await?;
    origin_task.await??;
    proxy_task.await??;
    Ok(response)
}

/// Benchmark one encrypted fakehttp tunnel round trip.
///
/// # Parameters
///
/// This function takes no parameters.
///
/// # Returns
///
/// Returns the full HTTP response bytes received through fakehttp.
///
/// # Errors
///
/// Returns an error when origin setup, fakehttp negotiation, AES-GCM framing,
/// request/response I/O, or spawned task completion fails.
async fn fakehttp_encrypted_round_trip() -> Result<Vec<u8>> {
    let (origin_addr, origin_task) = start_http_origin(b"OK").await?;
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let connector = Arc::new(Connector::new(None, None)?);
    let server_task = tokio::spawn(async move {
        fakehttp::serve(
            Box::new(server_side),
            connector,
            Some(FAKEHTTP_SECRET),
            fakehttp::DEFAULT_MAX_FRAME_SIZE,
        )
        .await
    });
    let endpoint = Target::new("127.0.0.1", 8080);
    let target = Target::new("127.0.0.1", origin_addr.port());
    let mut tunnel = fakehttp::connect(
        Box::new(client_side),
        &endpoint,
        &target,
        Some(FAKEHTTP_SECRET),
        fakehttp::DEFAULT_MAX_FRAME_SIZE,
        Duration::from_secs(10),
    )
    .await?;

    tunnel
        .write_all(format!("GET /bench HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n").as_bytes())
        .await?;
    tunnel.shutdown().await?;

    let mut response = Vec::new();
    tunnel.read_to_end(&mut response).await?;
    origin_task.await??;
    server_task.await??;
    Ok(response)
}

const RELAY_BULK_BYTES: usize = 256 * 1024;

/// Copy 256 KiB in each direction through the production relay.
///
/// # Parameters
///
/// * `payload` - Bytes written on both endpoints. Its length is the copy size.
///
/// # Returns
///
/// Returns the number of payload bytes read at both endpoints.
///
/// # Errors
///
/// Returns an error when socket setup, copying, or relay completion fails.
///
/// # Examples
///
/// ```text
/// let copied = relay_bulk_copy(payload).await?;
/// ```
async fn relay_bulk_copy(payload: Arc<Vec<u8>>) -> Result<usize> {
    let (left_peer, left_relay) = tcp_pair().await?;
    let (right_peer, right_relay) = tcp_pair().await?;
    for stream in [&left_peer, &left_relay, &right_peer, &right_relay] {
        stream.set_nodelay(true)?;
    }
    let relay_task = tokio::spawn(proxlet::connector::relay(
        Box::new(left_relay),
        Box::new(right_relay),
    ));
    let copy_len = payload.len();
    let payload_right = Arc::clone(&payload);
    let (mut left_read, mut left_write) = left_peer.into_split();
    let (mut right_read, mut right_write) = right_peer.into_split();
    let write_left = tokio::spawn(async move {
        left_write.write_all(&payload).await?;
        left_write.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    });
    let write_right = tokio::spawn(async move {
        right_write.write_all(&payload_right).await?;
        right_write.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    });
    let mut got_left = vec![0_u8; copy_len];
    let mut got_right = vec![0_u8; copy_len];
    tokio::try_join!(
        left_read.read_exact(&mut got_left),
        right_read.read_exact(&mut got_right),
    )?;
    write_left.await??;
    write_right.await??;
    relay_task.await??;
    black_box(got_left);
    black_box(got_right);
    Ok(copy_len * 2)
}

async fn tcp_pair() -> Result<(tokio::net::TcpStream, tokio::net::TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let connector = tokio::spawn(async move { tokio::net::TcpStream::connect(address).await });
    let (accepted, _) = listener.accept().await?;
    Ok((connector.await??, accepted))
}

/// Start a one-shot HTTP origin server.
///
/// # Parameters
///
/// * `body` - Static response body sent by the origin.
///
/// # Returns
///
/// Returns the origin address and a join handle for the origin task.
///
/// # Errors
///
/// Returns an error when binding the listener or reading its local address
/// fails.
async fn start_http_origin(body: &'static [u8]) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let _header = read_http_header(&mut stream).await?;
        stream
            .write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(),
            )
            .await?;
        stream.write_all(body).await?;
        Ok(())
    });
    Ok((address, task))
}

/// Start a one-shot TCP origin that replies after request EOF.
///
/// # Parameters
///
/// * `response` - Static bytes written back to the client.
///
/// # Returns
///
/// Returns the origin address and a join handle for the origin task.
///
/// # Errors
///
/// Returns an error when binding the listener or reading its local address
/// fails.
async fn start_echo_origin(
    response: &'static [u8],
) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await?;
        black_box(request);
        stream.write_all(response).await?;
        Ok(())
    });
    Ok((address, task))
}

/// Read an HTTP header from any async reader.
///
/// # Parameters
///
/// * `stream` - Async reader carrying an HTTP request or response.
///
/// # Returns
///
/// Returns the header bytes including CRLFCRLF.
///
/// # Errors
///
/// Returns an error when reading fails.
async fn read_http_header<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut header = Vec::with_capacity(256);
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await?;
        header.push(byte[0]);
    }
    Ok(header)
}

criterion_group!(benches, proxy_benches);
criterion_main!(benches);
