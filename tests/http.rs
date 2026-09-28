use std::sync::Arc;

use proxlet::connector::Connector;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn forwards_http_request_to_an_origin_server() {
    let origin = TcpListener::bind("127.0.0.1:0").await.expect("origin bind");
    let origin_addr = origin.local_addr().expect("origin address");
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.expect("origin accept");
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.expect("origin request");
            header.push(byte[0]);
        }
        assert!(header.starts_with(b"GET /ready HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .await
            .expect("origin response");
    });
    let (mut caller, proxy_client) = tokio::io::duplex(4096);
    let connector = Arc::new(Connector::new(None, None).expect("connector"));
    let proxy_task = tokio::spawn(async move {
        proxlet::http::serve(
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
            format!("GET http://{origin_addr}/ready HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .expect("proxy request");
    caller.shutdown().await.expect("request shutdown");
    let mut response = Vec::new();
    caller
        .read_to_end(&mut response)
        .await
        .expect("proxy response");

    origin_task.await.expect("origin task");
    proxy_task.await.expect("proxy task").expect("proxy result");
    assert!(response.ends_with(b"\r\n\r\nOK"));
}

async fn origin_request_header(path: &str) -> String {
    let origin = TcpListener::bind("127.0.0.1:0").await.expect("origin bind");
    let origin_addr = origin.local_addr().expect("origin address");
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.expect("origin accept");
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.expect("origin request");
            header.push(byte[0]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("origin response");
        String::from_utf8(header).expect("UTF-8")
    });
    let (mut caller, proxy_client) = tokio::io::duplex(4096);
    let connector = Arc::new(Connector::new(None, None).expect("connector"));
    let proxy_task = tokio::spawn(async move {
        proxlet::http::serve(
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
            format!("GET http://{origin_addr}{path} HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .expect("proxy request");
    caller.shutdown().await.expect("request shutdown");
    let mut response = Vec::new();
    caller
        .read_to_end(&mut response)
        .await
        .expect("proxy response");
    let header = origin_task.await.expect("origin task");
    proxy_task.await.expect("proxy task").expect("proxy result");
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    header
}

#[tokio::test]
async fn absolute_form_path_and_query_are_not_rewritten() {
    let dotted = "/foo/%2e./%2e%2e/.%2e/%2e.bar?x=%2e%2e";
    let header = origin_request_header(dotted).await;
    assert!(
        header.starts_with(&format!("GET {dotted} HTTP/1.1\r\n")),
        "{header}"
    );

    let slashed = "/foo\\bar";
    let header = origin_request_header(slashed).await;
    assert!(
        header.starts_with(&format!("GET {slashed} HTTP/1.1\r\n")),
        "{header}"
    );
}

#[tokio::test]
async fn origin_form_scanner_probe_receives_nginx_not_found() {
    let (mut caller, proxy_client) = tokio::io::duplex(4096);
    let connector = Arc::new(Connector::new(None, None).expect("connector"));
    let proxy_task = tokio::spawn(async move {
        proxlet::http::serve(
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
        .write_all(b"GET / HTTP/1.0\r\n\r\n")
        .await
        .expect("scanner probe");
    caller.shutdown().await.expect("probe shutdown");
    let mut response = Vec::new();
    caller
        .read_to_end(&mut response)
        .await
        .expect("scanner response");

    proxy_task.await.expect("proxy task").expect("proxy result");
    let text = String::from_utf8(response).expect("UTF-8");
    assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(text.contains("Server: nginx\r\n"));
    assert!(!text.contains("407"));
    assert!(!text.contains("502"));
}

#[tokio::test]
async fn proxy_request_with_unusable_target_returns_400() {
    let (mut caller, proxy_client) = tokio::io::duplex(4096);
    let connector = Arc::new(Connector::new(None, None).expect("connector"));
    let proxy_task = tokio::spawn(async move {
        proxlet::http::serve(
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
        .write_all(b"CONNECT example.com:99999 HTTP/1.1\r\n\r\n")
        .await
        .expect("bad port");
    caller.shutdown().await.expect("request shutdown");
    let mut response = Vec::new();
    caller
        .read_to_end(&mut response)
        .await
        .expect("proxy response");

    let _ = proxy_task.await.expect("proxy task");
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
}

#[tokio::test]
async fn pipelined_second_request_stays_off_the_first_origin() {
    let origin_a = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("origin A bind");
    let addr_a = origin_a.local_addr().expect("origin A address");
    let origin_b = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("origin B bind");
    let addr_b = origin_b.local_addr().expect("origin B address");
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

    let origin_a_task = tokio::spawn(async move {
        let (mut stream, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), origin_a.accept())
                .await
                .expect("origin A accept timed out")
                .expect("origin A accept");
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8; 1];
            stream
                .read_exact(&mut byte)
                .await
                .expect("origin A request");
            header.push(byte[0]);
        }
        let mut body = [0_u8; 4];
        stream.read_exact(&mut body).await.expect("origin A body");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut extra = [0_u8; 256];
        match stream.try_read(&mut extra) {
            Ok(0) => {}
            Ok(n) => panic!("origin A received extra bytes: {:?}", &extra[..n]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("origin A try_read: {error}"),
        }
        let text = String::from_utf8(header).expect("UTF-8 request");
        assert!(text.starts_with("POST /first HTTP/1.1\r\n"), "{text}");
        assert!(text.contains(&format!("Host: {addr_a}\r\n")), "{text}");
        assert!(text.contains("Connection: close\r\n"), "{text}");
        assert!(text.contains("X-Custom: 1\r\n"), "{text}");
        assert!(!text.contains("evil.example"), "{text}");
        assert!(!text.to_ascii_lowercase().contains("keep-alive"), "{text}");
        assert!(
            !text.to_ascii_lowercase().contains("proxy-authorization"),
            "{text}"
        );
        assert!(!text.to_ascii_lowercase().contains("te:"), "{text}");
        assert!(!text.to_ascii_lowercase().contains("upgrade:"), "{text}");
        assert_eq!(&body, b"body");
        ready_tx.send(()).expect("signal origin A ready");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nOK")
            .await
            .expect("origin A response");
    });

    let (mut caller, proxy_client) = tokio::io::duplex(8192);
    let connector = Arc::new(Connector::new(None, None).expect("connector"));
    let proxy_task = tokio::spawn(async move {
        proxlet::http::serve(
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
            format!(
                "POST http://{addr_a}/first HTTP/1.1\r\n\
                 Host: evil.example\r\n\
                 Content-Length: 4\r\n\
                 Connection: keep-alive\r\n\
                 Keep-Alive: timeout=5\r\n\
                 Proxy-Authorization: Basic abc\r\n\
                 TE: trailers\r\n\
                 Upgrade: websocket\r\n\
                 X-Custom: 1\r\n\
                 \r\n\
                 bodyGET http://{addr_b}/second HTTP/1.1\r\n\
                 Host: {addr_b}\r\n\
                 \r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("pipelined requests");

    ready_rx.await.expect("origin A ready");
    let accepted_b =
        tokio::time::timeout(std::time::Duration::from_millis(200), origin_b.accept()).await;
    assert!(accepted_b.is_err(), "second origin was contacted");

    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        caller.read_to_end(&mut response),
    )
    .await
    .expect("client read timed out")
    .expect("proxy response");
    origin_a_task.await.expect("origin A task");
    proxy_task.await.expect("proxy task").expect("proxy result");
    let text = String::from_utf8(response).expect("UTF-8 response");
    assert!(text.contains("Connection: close\r\n"), "{text}");
    assert!(!text.to_ascii_lowercase().contains("keep-alive"), "{text}");
    assert!(text.ends_with("\r\n\r\nOK"), "{text}");
}
