use std::sync::Arc;

use anyhow::{Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

use crate::cli::Auth;
use crate::connector::{BoxStream, Connector, Target, relay};

const MAX_HEADER_SIZE: usize = 64 * 1024;

pub async fn serve(
    mut client: BoxStream,
    initial: &[u8],
    connector: Arc<Connector>,
    auth: Option<&Auth>,
) -> Result<()> {
    let header = read_header(&mut client, initial).await?;
    let request = Request::parse(&header)?;
    if !request.is_authorized(auth) {
        client
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"proxlet\"\r\n\
                  Content-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await?;
        return Ok(());
    }

    let target = request.target()?;
    let mut remote = match connector.connect(&target).await {
        Ok(remote) => remote,
        Err(error) => {
            client
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
            return Err(error);
        }
    };

    if request.method.eq_ignore_ascii_case("CONNECT") {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    } else {
        remote.write_all(&request.origin_form_header()?).await?;
    }
    relay(client, remote).await?;
    Ok(())
}

async fn read_header(stream: &mut BoxStream, initial: &[u8]) -> Result<Vec<u8>> {
    let mut header = initial.to_vec();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= MAX_HEADER_SIZE {
            bail!("HTTP proxy request header exceeds {MAX_HEADER_SIZE} bytes")
        }
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await?;
        header.push(byte[0]);
    }
    Ok(header)
}

#[derive(Debug)]
struct Request {
    method: String,
    uri: String,
    version: String,
    headers: Vec<(String, String)>,
}

impl Request {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes)?;
        let mut lines = text.trim_end_matches("\r\n\r\n").split("\r\n");
        let request_line = lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("HTTP request has no request line"))?;
        let mut components = request_line.split_whitespace();
        let method = components.next().unwrap_or_default();
        let uri = components.next().unwrap_or_default();
        let version = components.next().unwrap_or_default();
        if method.is_empty() || uri.is_empty() || !version.starts_with("HTTP/") {
            bail!("invalid HTTP proxy request line")
        }
        let mut headers = Vec::new();
        for line in lines {
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("invalid HTTP header line"))?;
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
        Ok(Self {
            method: method.to_owned(),
            uri: uri.to_owned(),
            version: version.to_owned(),
            headers,
        })
    }

    fn is_authorized(&self, auth: Option<&Auth>) -> bool {
        let Some(auth) = auth else {
            return true;
        };
        let expected = BASE64.encode(format!("{}:{}", auth.username, auth.password));
        self.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("Proxy-Authorization")
                && value
                    .strip_prefix("Basic ")
                    .is_some_and(|provided| provided == expected)
        })
    }

    fn target(&self) -> Result<Target> {
        if self.method.eq_ignore_ascii_case("CONNECT") {
            return parse_authority(&self.uri, 443);
        }
        let uri = Url::parse(&self.uri)
            .map_err(|_| anyhow::anyhow!("forward proxy requests must use an absolute URI"))?;
        match uri.scheme() {
            "http" | "https" => {}
            scheme => bail!("unsupported HTTP request URI scheme: {scheme}"),
        }
        Ok(Target::new(
            uri.host_str()
                .ok_or_else(|| anyhow::anyhow!("HTTP URI is missing a host"))?,
            uri.port_or_known_default()
                .ok_or_else(|| anyhow::anyhow!("HTTP URI is missing a port"))?,
        ))
    }

    fn origin_form_header(&self) -> Result<Vec<u8>> {
        let uri = Url::parse(&self.uri)
            .map_err(|_| anyhow::anyhow!("forward proxy requests must use an absolute URI"))?;
        let mut path = uri.path().to_owned();
        if path.is_empty() {
            path.push('/');
        }
        if let Some(query) = uri.query() {
            path.push('?');
            path.push_str(query);
        }
        let mut rewritten = format!("{} {} {}\r\n", self.method, path, self.version);
        for (name, value) in &self.headers {
            if !name.eq_ignore_ascii_case("Proxy-Authorization")
                && !name.eq_ignore_ascii_case("Proxy-Connection")
            {
                rewritten.push_str(&format!("{name}: {value}\r\n"));
            }
        }
        rewritten.push_str("\r\n");
        Ok(rewritten.into_bytes())
    }
}

fn parse_authority(authority: &str, default_port: u16) -> Result<Target> {
    if authority.starts_with('[') {
        let closing = authority
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("invalid bracketed IPv6 authority"))?;
        let host = &authority[1..closing];
        let port = authority
            .get(closing + 1..)
            .and_then(|suffix| suffix.strip_prefix(':'))
            .map(str::parse)
            .transpose()?
            .unwrap_or(default_port);
        return Ok(Target::new(host, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Ok(Target::new(host, port.parse()?)),
        _ => Ok(Target::new(authority, default_port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn parses_connect_and_basic_auth() {
        let request = Request::parse(
            b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\n\r\n",
        )
        .expect("request");
        assert_eq!(
            request.target().expect("target"),
            Target::new("example.com", 443)
        );
        assert!(request.is_authorized(Some(&Auth {
            username: "u".to_owned(),
            password: "p".to_owned()
        })));
    }

    #[test]
    fn rewrites_absolute_uri_for_origin() {
        let request =
            Request::parse(b"GET http://example.com/a?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .expect("request");
        let rewritten =
            String::from_utf8(request.origin_form_header().expect("header")).expect("UTF-8 header");
        assert!(rewritten.starts_with("GET /a?q=1 HTTP/1.1\r\n"));
    }

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
        let proxy_task =
            tokio::spawn(async move { serve(Box::new(proxy_client), &[], connector, None).await });
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
}
