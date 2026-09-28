use std::sync::Arc;

use proxlet::connector::Connector;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn connects_and_relays_socks5_traffic() {
    let origin = TcpListener::bind("127.0.0.1:0").await.expect("origin bind");
    let port = origin.local_addr().expect("origin address").port();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.expect("origin accept");
        let mut input = Vec::new();
        stream.read_to_end(&mut input).await.expect("origin input");
        assert_eq!(input, b"hello");
        stream.write_all(b"world").await.expect("origin output");
    });
    let (mut caller, proxy_client) = tokio::io::duplex(4096);
    let connector = Arc::new(Connector::new(None, None).expect("connector"));
    let proxy_task = tokio::spawn(async move {
        proxlet::socks::serve(
            Box::new(proxy_client),
            None,
            connector,
            None,
            std::net::Ipv4Addr::LOCALHOST.into(),
            "socks5",
        )
        .await
    });

    caller.write_all(&[0x05, 0x01, 0x00]).await.expect("hello");
    let mut method = [0_u8; 2];
    caller.read_exact(&mut method).await.expect("method");
    assert_eq!(method, [0x05, 0x00]);
    let mut connect = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    connect.extend_from_slice(&port.to_be_bytes());
    caller.write_all(&connect).await.expect("connect");
    let mut reply = [0_u8; 10];
    caller.read_exact(&mut reply).await.expect("reply");
    assert_eq!(reply[1], 0x00);
    caller.write_all(b"hello").await.expect("payload");
    caller.shutdown().await.expect("payload shutdown");
    let mut output = Vec::new();
    caller.read_to_end(&mut output).await.expect("response");

    origin_task.await.expect("origin task");
    proxy_task.await.expect("proxy task").expect("proxy result");
    assert_eq!(output, b"world");
}

#[tokio::test]
async fn domain_with_control_characters_is_rejected_before_dial() {
    let (mut caller, proxy_client) = tokio::io::duplex(4096);
    let connector = Arc::new(Connector::new(None, None).expect("connector"));
    let proxy_task = tokio::spawn(async move {
        proxlet::socks::serve(
            Box::new(proxy_client),
            None,
            connector,
            None,
            std::net::Ipv4Addr::LOCALHOST.into(),
            "socks5",
        )
        .await
    });
    caller.write_all(&[0x05, 0x01, 0x00]).await.expect("hello");
    let mut method = [0_u8; 2];
    caller.read_exact(&mut method).await.expect("method");
    assert_eq!(method, [0x05, 0x00]);
    let domain = b"example.com\r\nProxy-Authorization: Basic eA==";
    let mut connect = vec![
        0x05,
        0x01,
        0x00,
        0x03,
        u8::try_from(domain.len()).expect("len"),
    ];
    connect.extend_from_slice(domain);
    connect.extend_from_slice(&80_u16.to_be_bytes());
    caller.write_all(&connect).await.expect("connect");
    let mut reply = [0_u8; 10];
    caller.read_exact(&mut reply).await.expect("reply");
    assert_eq!(reply[1], 0x01);
    let error = proxy_task.await.expect("task").expect_err("rejected");
    let text = error.to_string();
    assert!(text.contains("control character"), "{text}");
    assert!(!text.contains("Proxy-Authorization"), "{text}");
}

#[tokio::test]
async fn non_utf8_password_gets_auth_failure_reply() {
    let (mut caller, proxy_client) = tokio::io::duplex(256);
    let connector = Arc::new(Connector::new(None, None).expect("connector"));
    let auth = proxlet::cli::Auth {
        username: "alice".to_string(),
        password: "secret".to_string(),
    };
    let proxy_task = tokio::spawn(async move {
        proxlet::socks::serve(
            Box::new(proxy_client),
            None,
            connector,
            Some(&auth),
            std::net::Ipv4Addr::LOCALHOST.into(),
            "socks5",
        )
        .await
    });
    caller.write_all(&[0x05, 0x01, 0x02]).await.expect("hello");
    let mut method = [0_u8; 2];
    caller.read_exact(&mut method).await.expect("method");
    assert_eq!(method, [0x05, 0x02]);
    caller
        .write_all(&[0x01, 5, b'a', b'l', b'i', b'c', b'e', 1, 0xff])
        .await
        .expect("auth");
    let mut status = [0_u8; 2];
    caller.read_exact(&mut status).await.expect("auth status");
    assert_eq!(status, [0x01, 0x01]);
    let error = proxy_task.await.expect("join").expect_err("auth");
    assert!(error.to_string().contains("authentication"), "{error}");
}

#[tokio::test]
async fn non_utf8_domain_gets_connect_reply() {
    let (mut caller, proxy_client) = tokio::io::duplex(256);
    let connector = Arc::new(Connector::new(None, None).expect("connector"));
    let proxy_task = tokio::spawn(async move {
        proxlet::socks::serve(
            Box::new(proxy_client),
            None,
            connector,
            None,
            std::net::Ipv4Addr::LOCALHOST.into(),
            "socks5",
        )
        .await
    });
    caller.write_all(&[0x05, 0x01, 0x00]).await.expect("hello");
    let mut method = [0_u8; 2];
    caller.read_exact(&mut method).await.expect("method");
    assert_eq!(method, [0x05, 0x00]);
    caller
        .write_all(&[0x05, 0x01, 0x00, 0x03, 1, 0xff, 0, 80])
        .await
        .expect("connect");
    let mut reply = [0_u8; 10];
    caller.read_exact(&mut reply).await.expect("reply");
    assert_eq!(reply[1], 0x01);
    let error = proxy_task.await.expect("join").expect_err("domain");
    assert!(error.to_string().contains("UTF-8"), "{error}");
}

#[tokio::test]
async fn connection_refused_reply_is_connection_refused() {
    let (mut caller, proxy_client) = tokio::io::duplex(256);
    let connector = Arc::new(Connector::new(None, None).expect("connector"));
    let proxy_task = tokio::spawn(async move {
        proxlet::socks::serve(
            Box::new(proxy_client),
            None,
            connector,
            None,
            std::net::Ipv4Addr::LOCALHOST.into(),
            "socks5",
        )
        .await
    });
    caller.write_all(&[0x05, 0x01, 0x00]).await.expect("hello");
    let mut method = [0_u8; 2];
    caller.read_exact(&mut method).await.expect("method");
    assert_eq!(method, [0x05, 0x00]);
    caller
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 1])
        .await
        .expect("connect");
    let mut reply = [0_u8; 10];
    caller.read_exact(&mut reply).await.expect("reply");
    assert_eq!(reply[1], 0x05);
    proxy_task.await.expect("join").expect_err("refused");
}
