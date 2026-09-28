//! One-shot HTTP forward exchange.
//!
//! Non-CONNECT requests are rewritten, forwarded once, and closed. Later bytes
//! on the client connection are not copied to the origin.

use anyhow::{Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::connector::BoxStream;

use super::{MAX_HEADER_SIZE, read_header};

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Forward one absolute-form request and the matching origin response.
///
/// # Parameters
///
/// * `client` - Proxy client. Bytes after this request are left unread.
/// * `remote` - Origin connection.
/// * `method` - Client request method. `HEAD` responses have no body.
/// * `request_headers` - Original request headers, used only to frame the body.
/// * `origin_header` - Rewritten origin-form request header, including the blank line.
///
/// # Returns
///
/// Returns `Ok(())` after the origin response is written to the client.
///
/// # Errors
///
/// Returns an error when body forwarding or the origin response fails.
///
/// # Examples
///
/// ```ignore
/// forward::exchange(&mut client, &mut remote, &method, &headers, &origin_header).await?;
/// ```
pub(super) async fn exchange(
    client: &mut BoxStream,
    remote: &mut BoxStream,
    method: &str,
    request_headers: &[(String, String)],
    origin_header: &[u8],
) -> Result<()> {
    remote.write_all(origin_header).await?;
    forward_framed_body(client, remote, request_headers).await?;
    remote.flush().await?;
    // 请求体已经写完. 1xx 没有正文, 读到最终响应再写回客户端.
    let response = loop {
        let header = read_header(remote, &[]).await?;
        let response = Response::parse(&header)?;
        if response.status / 100 != 1 {
            break response;
        }
    };
    client
        .write_all(&response.connection_close_header())
        .await?;
    if response.has_body(method) {
        if body_is_framed(&response.headers) {
            forward_framed_body(remote, client, &response.headers).await?;
        } else {
            tokio::io::copy(remote, client).await?;
        }
    }
    Ok(())
}

/// Append end-to-end headers, an optional Host, and `Connection: close`.
///
/// # Parameters
///
/// * `out` - Buffer that already contains the start line and its CRLF.
/// * `headers` - Original header pairs.
/// * `host` - Origin authority for a request. `None` leaves a response Host untouched.
///
/// # Returns
///
/// This function does not return a value. `out` ends with the header blank line.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// append_forwarded_headers(&mut rewritten, &headers, Some("example.com:80"));
/// ```
pub(super) fn append_forwarded_headers(
    out: &mut String,
    headers: &[(String, String)],
    host: Option<&str>,
) {
    let chunked = is_chunked(headers);
    let connection_names = connection_option_names(headers);
    if let Some(host) = host {
        out.push_str("Host: ");
        out.push_str(host);
        out.push_str("\r\n");
    }
    for (name, value) in headers {
        if should_strip(name, &connection_names, chunked, host.is_some()) {
            continue;
        }
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    if chunked {
        // 分块是转发的帧格式, 不是 keep-alive. 原头已剥离, 这里补回一条.
        out.push_str("Transfer-Encoding: chunked\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
}

/// Parsed origin response header.
struct Response {
    status_line: String,
    status: u16,
    headers: Vec<(String, String)>,
}

impl Response {
    /// Parse an origin response header.
    ///
    /// # Parameters
    ///
    /// * `bytes` - Header bytes ending in CRLFCRLF.
    ///
    /// # Returns
    ///
    /// Returns the status line, status code, and headers.
    ///
    /// # Errors
    ///
    /// Returns an error when the header is not UTF-8 or the status line is invalid.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let response = Response::parse(b"HTTP/1.1 200 OK\r\n\r\n")?;
    /// ```
    fn parse(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes)?;
        let mut lines = text.trim_end_matches("\r\n\r\n").split("\r\n");
        let status_line = lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("HTTP response has no status line"))?
            .to_owned();
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or_else(|| anyhow::anyhow!("invalid HTTP status line"))?;
        let mut headers = Vec::new();
        for line in lines {
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("invalid HTTP header line"))?;
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
        Ok(Self {
            status_line,
            status,
            headers,
        })
    }

    /// Rewrite the response so the client does not reuse the connection.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed origin response.
    ///
    /// # Returns
    ///
    /// Returns header bytes with hop-by-hop fields removed and `Connection: close`.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// client.write_all(&response.connection_close_header()).await?;
    /// ```
    fn connection_close_header(&self) -> Vec<u8> {
        let mut rewritten = format!("{}\r\n", self.status_line);
        append_forwarded_headers(&mut rewritten, &self.headers, None);
        rewritten.into_bytes()
    }

    /// Report whether this response carries a message body.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed origin response.
    /// * `method` - Client request method. `HEAD` responses have no body.
    ///
    /// # Returns
    ///
    /// Returns `false` for `HEAD`, 1xx, 204, and 304 responses.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// if response.has_body("GET") { /* copy the body */ }
    /// ```
    fn has_body(&self, method: &str) -> bool {
        if method.eq_ignore_ascii_case("HEAD") {
            return false;
        }
        !matches!(self.status, 100..=199 | 204 | 304)
    }
}

/// Collect header names named by `Connection` or `Proxy-Connection`.
///
/// # Parameters
///
/// * `headers` - Header pairs to scan.
///
/// # Returns
///
/// Returns names that must be stripped, excluding the `close` and `keep-alive` tokens.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let names = connection_option_names(&headers);
/// ```
fn connection_option_names(headers: &[(String, String)]) -> Vec<String> {
    let mut names = Vec::new();
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("Connection")
            && !name.eq_ignore_ascii_case("Proxy-Connection")
        {
            continue;
        }
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty()
                || token.eq_ignore_ascii_case("close")
                || token.eq_ignore_ascii_case("keep-alive")
            {
                continue;
            }
            names.push(token.to_owned());
        }
    }
    names
}

/// Report whether a header must not be forwarded.
///
/// # Parameters
///
/// * `name` - Header name.
/// * `connection_names` - Extra names listed by `Connection`.
/// * `chunked` - Whether the body uses chunked framing.
/// * `replace_host` - Whether a new `Host` was already written.
///
/// # Returns
///
/// Returns `true` when the header is hop-by-hop, listed by `Connection`, a replaced `Host`,
/// or a request `Expect` header.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// if should_strip("Keep-Alive", &[], false, true) { /* drop */ }
/// ```
fn should_strip(
    name: &str,
    connection_names: &[String],
    chunked: bool,
    replace_host: bool,
) -> bool {
    if replace_host && (name.eq_ignore_ascii_case("Host") || name.eq_ignore_ascii_case("Expect")) {
        // 请求体随头一起发出, 不再转发 Expect, 避免 origin 先回 100 后双方等待.
        return true;
    }
    if chunked && name.eq_ignore_ascii_case("Content-Length") {
        return true;
    }
    if HOP_BY_HOP.iter().any(|hop| name.eq_ignore_ascii_case(hop)) {
        return true;
    }
    connection_names
        .iter()
        .any(|token| name.eq_ignore_ascii_case(token))
}

/// Report whether `Transfer-Encoding` contains `chunked`.
///
/// # Parameters
///
/// * `headers` - Header pairs to scan.
///
/// # Returns
///
/// Returns `true` when any `Transfer-Encoding` value includes a `chunked` token.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let chunked = is_chunked(&headers);
/// ```
fn is_chunked(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("Transfer-Encoding")
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
    })
}

/// Report whether the body length is explicit.
///
/// # Parameters
///
/// * `headers` - Header pairs to scan.
///
/// # Returns
///
/// Returns `true` for chunked bodies or a `Content-Length` header.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// if body_is_framed(&headers) { /* copy a framed body */ }
/// ```
fn body_is_framed(headers: &[(String, String)]) -> bool {
    is_chunked(headers)
        || headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("Content-Length"))
}

/// Parse a single `Content-Length` value.
///
/// # Parameters
///
/// * `headers` - Header pairs to scan.
///
/// # Returns
///
/// Returns the length when present.
///
/// # Errors
///
/// Returns an error when a value is not an integer or repeated values disagree.
///
/// # Examples
///
/// ```ignore
/// let length = content_length(&headers)?;
/// ```
fn content_length(headers: &[(String, String)]) -> Result<Option<u64>> {
    let mut found = None;
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("Content-Length") {
            continue;
        }
        let parsed = value
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("invalid Content-Length"))?;
        if let Some(previous) = found {
            if previous != parsed {
                bail!("conflicting Content-Length");
            }
        }
        found = Some(parsed);
    }
    Ok(found)
}

/// Copy a framed body without reading the next message.
///
/// # Parameters
///
/// * `from` - Stream that still has the body unread.
/// * `to` - Stream that receives the body.
/// * `headers` - Headers that describe the body framing.
///
/// # Returns
///
/// Returns `Ok(())` after the framed body is written. An unframed body is not read.
///
/// # Errors
///
/// Returns an error when the body ends early, chunk framing is invalid, or I/O fails.
///
/// # Examples
///
/// ```ignore
/// forward_framed_body(&mut client, &mut remote, &request.headers).await?;
/// ```
async fn forward_framed_body(
    from: &mut BoxStream,
    to: &mut BoxStream,
    headers: &[(String, String)],
) -> Result<()> {
    if is_chunked(headers) {
        return forward_chunked_body(from, to).await;
    }
    if let Some(len) = content_length(headers)? {
        copy_exact(from, to, len).await?;
    }
    Ok(())
}

/// Copy an exact number of body bytes.
///
/// # Parameters
///
/// * `from` - Source stream.
/// * `to` - Destination stream.
/// * `remaining` - Bytes still to copy.
///
/// # Returns
///
/// Returns `Ok(())` after `remaining` bytes are written.
///
/// # Errors
///
/// Returns an error when the source ends early or I/O fails.
///
/// # Examples
///
/// ```ignore
/// copy_exact(&mut from, &mut to, 4).await?;
/// ```
async fn copy_exact(from: &mut BoxStream, to: &mut BoxStream, mut remaining: u64) -> Result<()> {
    let mut buf = [0_u8; 8192];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let read = from.read(&mut buf[..want]).await?;
        if read == 0 {
            bail!("HTTP message body ended early");
        }
        to.write_all(&buf[..read]).await?;
        remaining -= read as u64;
    }
    Ok(())
}

/// Forward one chunked body, including the terminating chunk and trailers.
///
/// # Parameters
///
/// * `from` - Source stream positioned at the first chunk-size line.
/// * `to` - Destination stream.
///
/// # Returns
///
/// Returns `Ok(())` after the chunk terminator and trailer block are written.
///
/// # Errors
///
/// Returns an error when a chunk line is malformed, the body ends early, or I/O fails.
///
/// # Examples
///
/// ```ignore
/// forward_chunked_body(&mut from, &mut to).await?;
/// ```
async fn forward_chunked_body(from: &mut BoxStream, to: &mut BoxStream) -> Result<()> {
    loop {
        let line = read_crlf_line(from).await?;
        to.write_all(&line).await?;
        let size_text = std::str::from_utf8(&line)?;
        let size_text = size_text.trim().split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(size_text, 16)
            .map_err(|_| anyhow::anyhow!("invalid HTTP chunk size"))?;
        if size == 0 {
            loop {
                let trailer = read_crlf_line(from).await?;
                to.write_all(&trailer).await?;
                if trailer == b"\r\n" {
                    return Ok(());
                }
            }
        }
        copy_exact(from, to, size).await?;
        let mut crlf = [0_u8; 2];
        from.read_exact(&mut crlf).await?;
        if &crlf != b"\r\n" {
            bail!("HTTP chunk missing CRLF");
        }
        to.write_all(&crlf).await?;
    }
}

/// Read one CRLF-terminated line.
///
/// # Parameters
///
/// * `stream` - Stream to read.
///
/// # Returns
///
/// Returns the line, including the trailing CRLF.
///
/// # Errors
///
/// Returns an error when the line exceeds the header limit, the stream ends, or I/O fails.
///
/// # Examples
///
/// ```ignore
/// let line = read_crlf_line(&mut stream).await?;
/// ```
async fn read_crlf_line(stream: &mut BoxStream) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        if line.len() >= MAX_HEADER_SIZE {
            bail!("HTTP line exceeds limit");
        }
        let mut byte = [0_u8; 1];
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            bail!("HTTP line ended early");
        }
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
    }
}
