//! HTTP forward proxy listener implementation.
//! Parses requests, rejects CR/LF/NUL headers, rewrites absolute-form, and relays CONNECT.

mod chain;
mod forward;

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{bail, Result};
use tokio::io::AsyncWriteExt;
use url::Url;

use crate::camouflage;
use crate::cli::Auth;
use crate::connector::{relay, with_timeout, BoxStream, Connector, Target};

pub(super) const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Serve one HTTP proxy client connection.
///
/// # Parameters
///
/// * `client` - Accepted client stream.
/// * `initial` - Bytes already read by mixed-mode protocol detection.
/// * `connector` - Connector used to reach the target or upstream proxy.
/// * `auth` - Optional listener Basic authentication credentials.
/// * `peer` - Client IP recorded in the access log. The password is never logged.
/// * `protocol` - Access-log protocol token, such as `http` or `https`.
///
/// # Returns
///
/// Returns `Ok(())` after the connection finishes.
///
/// # Errors
///
/// Returns an error when request parsing, authentication response writing,
/// target connection, header rewriting, relay, or the closing shutdown fails.
/// A non-CONNECT `https://` absolute-form request is rejected before dialing.
///
/// # Examples
///
/// ```ignore
/// http::serve(client, &[], connector, None, peer, "http").await?;
/// ```
pub async fn serve(
    mut client: BoxStream,
    initial: &[u8],
    connector: Arc<Connector>,
    auth: Option<&Auth>,
    peer: IpAddr,
    protocol: &str,
) -> Result<()> {
    let header = match with_timeout(
        connector.connect_timeout(),
        "HTTP request header",
        read_header(&mut client, initial),
    )
    .await
    {
        Ok(header) => header,
        Err(_) => {
            // 客户端仍回伪装 404. 服务端只记失败, 不记原始头.
            crate::access::record(peer, protocol, None, "bad-request");
            let _ = camouflage::write_not_found(&mut client).await;
            return Ok(());
        }
    };
    let request = match Request::parse(&header) {
        Ok(request) => request,
        Err(_) => {
            crate::access::record(peer, protocol, None, "bad-request");
            camouflage::write_not_found(&mut client).await?;
            return Ok(());
        }
    };
    if chain::request_has_control_header(&request.headers) {
        crate::access::record(peer, protocol, None, "bad-request");
        camouflage::write_proxy_status(&mut client, "400 Bad Request").await?;
        return Ok(());
    }
    // nmap GetRequest/HTTPOptions use origin-form paths such as `GET /`.
    // Answer those as a normal web server instead of leaking proxy errors.
    if !request.is_proxy_request() {
        crate::access::record(peer, protocol, None, "not-proxy");
        camouflage::write_not_found(&mut client).await?;
        return Ok(());
    }
    if !request.is_authorized(auth) {
        let target = request.target().ok().map(|target| target.authority());
        // 先落日志再回 407, 避免客户端先看到响应而日志还在缓冲里.
        crate::access::record(peer, protocol, target.as_deref(), "auth-failed");
        with_timeout(
            connector.connect_timeout(),
            "proxy authentication response",
            client.write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"proxlet\"\r\n\
                  Content-Length: 0\r\nConnection: close\r\n\r\n",
            ),
        )
        .await?;
        return Ok(());
    }
    if !request.method.eq_ignore_ascii_case("CONNECT")
        && (request.uri.starts_with("https://") || request.uri.starts_with("HTTPS://"))
    {
        let logged = request.target().ok().map(|target| target.authority());
        crate::access::record(peer, protocol, logged.as_deref(), "bad-request");
        with_timeout(
            connector.connect_timeout(),
            "https absolute-form rejection",
            client.write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ),
        )
        .await?;
        bail!("https absolute-form requires CONNECT");
    }
    let target = match request.target() {
        Ok(target) => target,
        Err(error) => {
            crate::access::record(peer, protocol, None, "bad-request");
            let _ = camouflage::write_proxy_status(&mut client, "400 Bad Request").await;
            return Err(error);
        }
    };
    let logged = target.authority();
    if !request.method.eq_ignore_ascii_case("CONNECT")
        && chain::try_forward(&mut client, &request, &target, &connector, peer, protocol).await?
    {
        return Ok(());
    }
    let mut remote = match connector.connect(&target).await {
        Ok(remote) => remote,
        Err(error) => {
            camouflage::write_proxy_status(&mut client, "502 Bad Gateway").await?;
            crate::access::record(peer, protocol, Some(&logged), "error");
            return Err(error);
        }
    };

    if request.method.eq_ignore_ascii_case("CONNECT") {
        with_timeout(
            connector.connect_timeout(),
            "CONNECT response",
            client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
        )
        .await?;
        if let Err(error) = relay(client, remote).await {
            crate::access::record(peer, protocol, Some(&logged), "error");
            return Err(error.into());
        }
        crate::access::record(peer, protocol, Some(&logged), "ok");
        return Ok(());
    }

    // 不 relay. 流水线里的下一个请求必须留在客户端, 不能拷到第一个 origin.
    // drop 不会发送 TLS close_notify, 客户端 read_to_end 会报 unexpected eof.
    let origin_header = match request.origin_form_header() {
        Ok(header) => header,
        Err(error) => {
            crate::access::record(peer, protocol, Some(&logged), "bad-request");
            let _ = camouflage::write_proxy_status(&mut client, "400 Bad Request").await;
            return Err(error);
        }
    };
    if let Err(error) = forward::exchange(
        &mut client,
        &mut remote,
        &request.method,
        &request.headers,
        &origin_header,
        connector.connect_timeout(),
    )
    .await
    {
        crate::access::record(peer, protocol, Some(&logged), "error");
        return Err(error);
    }
    client.shutdown().await?;
    remote.shutdown().await?;
    crate::access::record(peer, protocol, Some(&logged), "ok");
    Ok(())
}

/// Read an HTTP message header.
///
/// # Parameters
///
/// * `stream` - Stream to read.
/// * `initial` - Bytes already consumed by protocol detection.
///
/// # Returns
///
/// Returns header bytes including CRLFCRLF.
///
/// # Errors
///
/// Returns an error when the header exceeds the limit, the peer closes early,
/// or I/O fails.
///
/// # Examples
///
/// ```ignore
/// let header = read_header(&mut stream, &[]).await?;
/// ```
pub(super) async fn read_header(stream: &mut BoxStream, initial: &[u8]) -> Result<Vec<u8>> {
    crate::bufio::read_until(
        stream,
        initial,
        b"\r\n\r\n",
        MAX_HEADER_SIZE,
        "HTTP proxy request header",
    )
    .await
}

#[derive(Debug)]
/// Parsed HTTP proxy request header.
struct Request {
    method: String,
    uri: String,
    version: String,
    headers: Vec<(String, String)>,
}

impl Request {
    /// Parse an HTTP proxy request header.
    ///
    /// # Parameters
    ///
    /// * `bytes` - Header bytes ending in CRLFCRLF.
    ///
    /// # Returns
    ///
    /// Returns a parsed [`Request`].
    ///
    /// # Errors
    ///
    /// Returns an error when the header is not UTF-8, the request line is
    /// invalid, or a header line is malformed.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let request = Request::parse(b"GET http://example.com/ HTTP/1.1\r\n\r\n")?;
    /// ```
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

    /// Check whether this request is a forward-proxy CONNECT or absolute-URI.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed HTTP request.
    ///
    /// # Returns
    ///
    /// Returns `true` for CONNECT or absolute-form `http(s)://` requests.
    /// Origin-form scanner probes such as `GET /` return `false`.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert!(request.is_proxy_request());
    /// ```
    fn is_proxy_request(&self) -> bool {
        self.method.eq_ignore_ascii_case("CONNECT")
            || self.uri.starts_with("http://")
            || self.uri.starts_with("https://")
            || self.uri.starts_with("HTTP://")
            || self.uri.starts_with("HTTPS://")
    }

    /// Check listener Basic authentication for this request.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed HTTP request.
    /// * `auth` - Optional expected credentials.
    ///
    /// # Returns
    ///
    /// Returns `true` when authentication is disabled or credentials match.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert!(request.is_authorized(Some(&auth)));
    /// ```
    fn is_authorized(&self, auth: Option<&Auth>) -> bool {
        let Some(auth) = auth else {
            return true;
        };
        self.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("Proxy-Authorization")
                && crate::secret::basic_authorization_matches(value, &auth.username, &auth.password)
        })
    }

    /// Determine the target endpoint requested by the HTTP proxy client.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed HTTP request.
    ///
    /// # Returns
    ///
    /// Returns the target endpoint for CONNECT or absolute-form HTTP requests.
    ///
    /// # Errors
    ///
    /// Returns an error when the URI is invalid, lacks host/port information, or
    /// uses an unsupported scheme.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let target = request.target()?;
    /// ```
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

    /// Rewrite an absolute-form request header to origin-form for the origin server.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed absolute-form HTTP request.
    ///
    /// # Returns
    /// Returns rewritten header bytes suitable for the origin server. Path and
    /// query are copied unchanged. `Host` matches the target authority,
    /// hop-by-hop headers are removed, and `Connection: close` is set.
    ///
    /// # Errors
    ///
    /// Returns an error when the request URI is not a valid absolute URI.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let header = request.origin_form_header()?;
    /// ```
    fn origin_form_header(&self) -> Result<Vec<u8>> {
        let path = forward::raw_origin_target(&self.uri)?;
        let authority = self.target()?.authority();
        let mut rewritten = format!("{} {} {}\r\n", self.method, path, self.version);
        forward::append_forwarded_headers(&mut rewritten, &self.headers, Some(&authority));
        Ok(rewritten.into_bytes())
    }
}

/// Parse an HTTP authority into a target.
///
/// # Parameters
///
/// * `authority` - Authority text from CONNECT or URI host data.
/// * `default_port` - Port used when the authority omits one.
///
/// # Returns
///
/// Returns the parsed target.
///
/// # Errors
///
/// Returns an error when the authority contains a control character, an
/// unbracketed IPv6 address, or a malformed port. Control-character errors
/// do not include the authority.
///
/// # Examples
///
/// ```ignore
/// let target = parse_authority("example.com:443", 80)?;
/// ```
fn parse_authority(authority: &str, default_port: u16) -> Result<Target> {
    Target::reject_control_chars(authority)?;
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
        Some(_) => bail!("unbracketed IPv6 authority"),
        None => Ok(Target::new(authority, default_port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(request.is_proxy_request());
    }

    #[test]
    fn rewrites_absolute_uri_for_origin() {
        let request =
            Request::parse(b"GET http://example.com/a?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .expect("request");
        let rewritten =
            String::from_utf8(request.origin_form_header().expect("header")).expect("UTF-8 header");
        assert!(rewritten.starts_with("GET /a?q=1 HTTP/1.1\r\n"));
        assert!(rewritten.contains("Host: example.com:80\r\n"));
        assert!(rewritten.contains("Connection: close\r\n"));
        assert!(request.is_proxy_request());
    }

    #[test]
    fn strips_hop_by_hop_headers_and_connection_tokens() {
        let request = Request::parse(
            b"GET http://example.com/a HTTP/1.1\r\n\
              Host: evil.example\r\n\
              Connection: keep-alive, X-Foo\r\n\
              Keep-Alive: timeout=5\r\n\
              X-Foo: drop\r\n\
              X-Bar: keep\r\n\
              Proxy-Authorization: Basic abc\r\n\
              TE: trailers\r\n\
              Upgrade: websocket\r\n\
              Expect: 100-continue\r\n\
              \r\n",
        )
        .expect("request");
        let rewritten =
            String::from_utf8(request.origin_form_header().expect("header")).expect("UTF-8 header");
        assert!(
            rewritten.contains("Host: example.com:80\r\n"),
            "{rewritten}"
        );
        assert!(rewritten.contains("Connection: close\r\n"), "{rewritten}");
        assert!(rewritten.contains("X-Bar: keep\r\n"), "{rewritten}");
        assert!(!rewritten.contains("evil.example"), "{rewritten}");
        assert!(!rewritten.contains("X-Foo"), "{rewritten}");
        assert!(
            !rewritten.to_ascii_lowercase().contains("keep-alive"),
            "{rewritten}"
        );
        assert!(
            !rewritten
                .to_ascii_lowercase()
                .contains("proxy-authorization"),
            "{rewritten}"
        );
        assert!(
            !rewritten.to_ascii_lowercase().contains("te:"),
            "{rewritten}"
        );
        assert!(
            !rewritten.to_ascii_lowercase().contains("upgrade:"),
            "{rewritten}"
        );
        assert!(
            !rewritten.to_ascii_lowercase().contains("expect:"),
            "{rewritten}"
        );
    }

    #[test]
    fn keeps_chunked_framing_and_drops_content_length() {
        let request = Request::parse(
            b"POST http://example.com/a HTTP/1.1\r\n\
              Transfer-Encoding: chunked\r\n\
              Content-Length: 5\r\n\
              \r\n",
        )
        .expect("request");
        let rewritten =
            String::from_utf8(request.origin_form_header().expect("header")).expect("UTF-8 header");
        assert!(
            rewritten.contains("Transfer-Encoding: chunked\r\n"),
            "{rewritten}"
        );
        assert!(
            !rewritten.to_ascii_lowercase().contains("content-length"),
            "{rewritten}"
        );
        assert!(rewritten.contains("Connection: close\r\n"), "{rewritten}");
    }

    #[test]
    fn treats_origin_form_scanner_probe_as_non_proxy() {
        let request = Request::parse(b"GET / HTTP/1.0\r\n\r\n").expect("request");
        assert!(!request.is_proxy_request());
    }

    #[test]
    fn rejects_control_characters_in_connect_authority() {
        let request = Request::parse(b"CONNECT example.com\x00.evil:80 HTTP/1.1\r\n\r\n")
            .expect("request line");
        let error = request.target().expect_err("control");
        let text = error.to_string();
        assert!(text.contains("control character"), "{text}");
        assert!(!text.contains("evil"), "{text}");
        let bare = Request::parse(b"CONNECT 2001:db8::1:443 HTTP/1.1\r\n\r\n").expect("line");
        assert!(bare
            .target()
            .expect_err("bare")
            .to_string()
            .contains("unbracketed IPv6"));
    }

    #[tokio::test]
    async fn rejects_https_absolute_form_before_dialing() {
        use tokio::io::AsyncReadExt;
        let (client, mut caller) = tokio::io::duplex(1024);
        let connector = Arc::new(Connector::new(None, None).expect("connector"));
        let serve = tokio::spawn(serve(
            Box::new(client),
            &[],
            connector,
            None,
            "127.0.0.1".parse().expect("peer"),
            "http",
        ));
        caller
            .write_all(b"GET https://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
            .await
            .expect("write");
        let mut buf = [0_u8; 128];
        let n = caller.read(&mut buf).await.expect("read");
        let text = String::from_utf8_lossy(&buf[..n]);
        assert!(text.starts_with("HTTP/1.1 400"), "{text}");
        let error = serve.await.expect("join").expect_err("rejected");
        assert!(error.to_string().contains("https absolute-form"), "{error}");
    }
}
