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
        proxlet::http::serve(Box::new(proxy_client), &[], connector, None).await
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
