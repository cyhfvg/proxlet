//! fakehttp proxlet-to-proxlet transport implementation.
//!
//! fakehttp wraps arbitrary proxy traffic in HTTP-looking requests and
//! responses. When an AES secret is configured, payload frames are encrypted
//! with AES-256-GCM using deterministic parameters derived from the secret and
//! per-session token.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::camouflage;
use crate::connector::{BoxStream, Connector, Target, relay};

mod chunked;
mod crypto;

use chunked::chunked_body_stream;
pub use crypto::CryptoRole;
use crypto::encrypt_stream;

const MAX_HEADER_SIZE: usize = 64 * 1024;
/// Default fakehttp encrypted frame payload size in bytes.
pub const DEFAULT_MAX_FRAME_SIZE: usize = 16 * 1024;
const MAX_SUPPORTED_FRAME_SIZE: usize = 64 * 1024;
const SALT_SIZE: usize = 16;
const FAKEHTTP_PATH_PREFIX: &str = "/api/v1/stream/";
const CRYPTO_ENCODING: &str = "aes-256-gcm";
const MAX_FRAME_SIZE_HEADER: &str = "X-Proxlet-Max-Frame-Size";
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Serve one inbound fakehttp tunnel from a downstream proxlet.
///
/// # Parameters
///
/// * `client` - Accepted stream from the downstream proxlet.
/// * `connector` - Connector used to dial the final target.
/// * `aes_secret` - Optional AES secret required for encrypted tunnels.
/// * `max_frame_size` - Listener-side maximum encrypted frame payload size.
///
/// # Returns
///
/// Returns `Ok(())` after the tunneled connection finishes.
///
/// # Errors
///
/// Returns an error when the fakehttp request is invalid, encryption policy does
/// not match, target connection fails, HTTP response writing fails, or relaying
/// traffic fails.
pub async fn serve(
    mut client: BoxStream,
    connector: Arc<Connector>,
    aes_secret: Option<&str>,
    max_frame_size: usize,
) -> Result<()> {
    let header = match read_header(&mut client).await {
        Ok(header) => header,
        Err(_) => {
            let _ = camouflage::write_not_found(&mut client).await;
            return Ok(());
        }
    };
    let request = match Request::parse(&header) {
        Ok(request) => request,
        Err(_) => {
            camouflage::write_not_found(&mut client).await?;
            return Ok(());
        }
    };
    let target = match request.target() {
        Ok(target) => target,
        Err(_) => {
            camouflage::write_not_found(&mut client).await?;
            return Ok(());
        }
    };
    let session = match request.session() {
        Ok(session) => session,
        Err(_) => {
            camouflage::write_not_found(&mut client).await?;
            return Ok(());
        }
    };
    let negotiated_frame_size = match request.max_frame_size() {
        Ok(size) => size
            .unwrap_or(DEFAULT_MAX_FRAME_SIZE)
            .min(normalize_max_frame_size(max_frame_size)),
        Err(_) => {
            camouflage::write_not_found(&mut client).await?;
            return Ok(());
        }
    };
    let wants_crypto = request.wants_crypto();
    let crypto_secret = match (wants_crypto, aes_secret) {
        (true, Some(secret)) => Some(secret),
        (true, None) | (false, Some(_)) => {
            camouflage::write_not_found(&mut client).await?;
            bail!("fakehttp encryption policy mismatch")
        }
        (false, None) => None,
    };

    // Reply with a normal-looking HTTP error when target dialing fails, then
    // propagate the original error to the server log.
    let remote = match connector.connect(&target).await {
        Ok(remote) => remote,
        Err(error) => {
            camouflage::write_service_unavailable(&mut client).await?;
            return Err(error);
        }
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Server: nginx\r\n\
         Content-Type: application/octet-stream\r\n\
         Transfer-Encoding: chunked\r\n\
         Cache-Control: no-store\r\n\
         {MAX_FRAME_SIZE_HEADER}: {negotiated_frame_size}\r\n\
         Connection: keep-alive\r\n\r\n",
    );
    client.write_all(response.as_bytes()).await?;
    let client = chunked_body_stream(client);
    let client = match crypto_secret {
        Some(secret) => encrypt_stream(
            client,
            secret,
            &session,
            CryptoRole::Server,
            negotiated_frame_size,
        )?,
        None => client,
    };
    // After the HTTP handshake, both directions become raw tunneled streams.
    relay(client, remote).await?;
    Ok(())
}

/// Connect to an upstream fakehttp listener and return a tunneled stream.
///
/// # Parameters
///
/// * `stream` - Connected TCP stream to the upstream fakehttp listener.
/// * `endpoint` - fakehttp listener endpoint used for the HTTP Host header.
/// * `target` - Final destination requested by the local client.
/// * `aes_secret` - Optional AES secret used to encrypt payload frames.
/// * `max_frame_size` - Downstream maximum encrypted frame payload size.
///
/// # Returns
///
/// Returns a boxed stream that carries plaintext target traffic.
///
/// # Errors
///
/// Returns an error when request writing, fakehttp response parsing,
/// negotiation, or crypto stream initialization fails.
pub async fn connect(
    mut stream: BoxStream,
    endpoint: &Target,
    target: &Target,
    aes_secret: Option<&str>,
    max_frame_size: usize,
) -> Result<BoxStream> {
    let max_frame_size = normalize_max_frame_size(max_frame_size);
    let session = session_token(target);
    let request = request_header(
        endpoint,
        target,
        aes_secret.is_some(),
        &session,
        max_frame_size,
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let header = read_header(&mut stream).await?;
    let response = Response::parse(&header)?;
    if !response.status.contains(" 200 ") {
        bail!("fakehttp upstream rejected tunnel: {}", response.status)
    }
    let negotiated_frame_size = response
        .max_frame_size()?
        .unwrap_or(DEFAULT_MAX_FRAME_SIZE)
        .min(max_frame_size);
    let stream = chunked_body_stream(stream);
    match aes_secret {
        Some(secret) => encrypt_stream(
            stream,
            secret,
            &session,
            CryptoRole::Client,
            negotiated_frame_size,
        ),
        None => Ok(stream),
    }
}

/// Build the HTTP request header used to open a fakehttp tunnel.
///
/// # Parameters
///
/// * `endpoint` - Upstream fakehttp endpoint.
/// * `target` - Final destination encoded into the URL path.
/// * `encrypted` - Whether to advertise AES-256-GCM frame encoding.
/// * `session` - Per-tunnel session token.
/// * `max_frame_size` - Requested maximum payload frame size in bytes.
///
/// # Returns
///
/// Returns a complete HTTP request header ending in CRLFCRLF.
///
/// # Errors
///
/// This function does not return errors.
fn request_header(
    endpoint: &Target,
    target: &Target,
    encrypted: bool,
    session: &str,
    max_frame_size: usize,
) -> String {
    let target_token = URL_SAFE_NO_PAD.encode(target.authority());
    let mut request = format!(
        "POST {FAKEHTTP_PATH_PREFIX}{session}/{target_token} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: Mozilla/5.0\r\n\
         Accept: */*\r\n\
         Content-Type: application/octet-stream\r\n\
         Transfer-Encoding: chunked\r\n\
         Cache-Control: no-cache\r\n",
        endpoint.authority()
    );
    if encrypted {
        request.push_str(&format!("Content-Encoding: {CRYPTO_ENCODING}\r\n"));
    }
    request.push_str(&format!("{MAX_FRAME_SIZE_HEADER}: {max_frame_size}\r\n"));
    request.push_str("Connection: keep-alive\r\n\r\n");
    request
}

/// Generate a per-tunnel session token.
///
/// # Parameters
///
/// * `target` - Final destination included in the token input.
///
/// # Returns
///
/// Returns a URL-safe token used in the fakehttp request path and crypto
/// derivation.
///
/// # Errors
///
/// This function does not return errors.
fn session_token(target: &Target) -> String {
    let counter = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let digest = Sha256::digest(
        [
            b"proxlet fakehttp session\0".as_slice(),
            &now.to_be_bytes(),
            &counter.to_be_bytes(),
            &std::process::id().to_be_bytes(),
            target.authority().as_bytes(),
        ]
        .concat(),
    );
    URL_SAFE_NO_PAD.encode(&digest[..SALT_SIZE])
}

/// Read an HTTP header from a fakehttp stream.
///
/// # Parameters
///
/// * `stream` - Stream to read from.
///
/// # Returns
///
/// Returns header bytes including the CRLFCRLF terminator.
///
/// # Errors
///
/// Returns an error when the header exceeds the configured limit, the stream
/// ends early, or I/O fails.
async fn read_header(stream: &mut BoxStream) -> Result<Vec<u8>> {
    let mut header = Vec::with_capacity(256);
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= MAX_HEADER_SIZE {
            bail!("fakehttp header exceeds {MAX_HEADER_SIZE} bytes")
        }
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await?;
        header.push(byte[0]);
    }
    Ok(header)
}

#[derive(Debug)]
/// Parsed inbound fakehttp HTTP request.
struct Request {
    path: String,
    headers: Vec<(String, String)>,
}

impl Request {
    /// Parse a fakehttp HTTP request header.
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
    /// Returns an error when the header is not UTF-8, lacks a valid request
    /// line, uses an unsupported method/path/version, or contains malformed
    /// header lines.
    fn parse(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes)?;
        let mut lines = text.trim_end_matches("\r\n\r\n").split("\r\n");
        let request_line = lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("fakehttp request has no request line"))?;
        let mut components = request_line.split_whitespace();
        let method = components.next().unwrap_or_default();
        let path = components.next().unwrap_or_default();
        let version = components.next().unwrap_or_default();
        if !method.eq_ignore_ascii_case("POST") || path.is_empty() || !version.starts_with("HTTP/")
        {
            bail!("invalid fakehttp request line")
        }
        let mut headers = Vec::new();
        for line in lines {
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("invalid fakehttp header line"))?;
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
        Ok(Self {
            path: path.to_owned(),
            headers,
        })
    }

    /// Decode the final target from the fakehttp request path.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed fakehttp request.
    ///
    /// # Returns
    ///
    /// Returns the decoded target endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is malformed, the target token is invalid,
    /// or the decoded authority is invalid.
    fn target(&self) -> Result<Target> {
        let (_, token) = self.path_parts()?;
        let authority = String::from_utf8(URL_SAFE_NO_PAD.decode(token)?)?;
        parse_authority(&authority)
    }

    /// Extract the fakehttp session token from the request path.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed fakehttp request.
    ///
    /// # Returns
    ///
    /// Returns the session token.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is malformed or the session token is
    /// empty.
    fn session(&self) -> Result<String> {
        let (session, _) = self.path_parts()?;
        if session.is_empty() {
            bail!("fakehttp session token is empty")
        }
        Ok(session.to_owned())
    }

    /// Split the fakehttp path suffix into session and target token.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed fakehttp request.
    ///
    /// # Returns
    ///
    /// Returns `(session, target_token)`.
    ///
    /// # Errors
    ///
    /// Returns an error when the path prefix or separator is missing.
    fn path_parts(&self) -> Result<(&str, &str)> {
        let suffix = self
            .path
            .strip_prefix(FAKEHTTP_PATH_PREFIX)
            .ok_or_else(|| anyhow::anyhow!("fakehttp request path is not supported"))?;
        suffix
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("fakehttp request path is missing session or target"))
    }

    /// Check whether the request asks for AES-256-GCM payload encoding.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed fakehttp request.
    ///
    /// # Returns
    ///
    /// Returns `true` when `Content-Encoding` matches the fakehttp crypto value.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    fn wants_crypto(&self) -> bool {
        self.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("Content-Encoding")
                && value.eq_ignore_ascii_case(CRYPTO_ENCODING)
        })
    }

    /// Parse the requested fakehttp frame size header.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed fakehttp request.
    ///
    /// # Returns
    ///
    /// Returns the requested frame size when present.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame size header is not numeric or is outside
    /// the supported range.
    fn max_frame_size(&self) -> Result<Option<usize>> {
        parse_max_frame_size_header(&self.headers)
    }
}

#[derive(Debug)]
/// Parsed upstream fakehttp HTTP response.
struct Response {
    status: String,
    headers: Vec<(String, String)>,
}

impl Response {
    /// Parse a fakehttp HTTP response header.
    ///
    /// # Parameters
    ///
    /// * `bytes` - Header bytes ending in CRLFCRLF.
    ///
    /// # Returns
    ///
    /// Returns a parsed [`Response`].
    ///
    /// # Errors
    ///
    /// Returns an error when the response is not UTF-8, lacks a status line, or
    /// contains malformed header lines.
    fn parse(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes)?;
        let mut lines = text.trim_end_matches("\r\n\r\n").split("\r\n");
        let status = lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("fakehttp response has no status line"))?;
        let mut headers = Vec::new();
        for line in lines {
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("invalid fakehttp response header line"))?;
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
        Ok(Self {
            status: status.to_owned(),
            headers,
        })
    }

    /// Parse the negotiated fakehttp frame size header.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed fakehttp response.
    ///
    /// # Returns
    ///
    /// Returns the negotiated frame size when present.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame size header is not numeric or is outside
    /// the supported range.
    fn max_frame_size(&self) -> Result<Option<usize>> {
        parse_max_frame_size_header(&self.headers)
    }
}

/// Parse a fakehttp frame-size header from an HTTP header list.
///
/// # Parameters
///
/// * `headers` - Parsed HTTP header pairs.
///
/// # Returns
///
/// Returns the frame size when the header is present.
///
/// # Errors
///
/// Returns an error when the header value is invalid.
fn parse_max_frame_size_header(headers: &[(String, String)]) -> Result<Option<usize>> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(MAX_FRAME_SIZE_HEADER))
        .map(|(_, value)| parse_max_frame_size(value))
        .transpose()
}

/// Parse a frame-size header value in bytes.
///
/// # Parameters
///
/// * `value` - Header value to parse.
///
/// # Returns
///
/// Returns the parsed frame size in bytes.
///
/// # Errors
///
/// Returns an error when `value` is not numeric or is outside the supported
/// range.
fn parse_max_frame_size(value: &str) -> Result<usize> {
    let size = value.parse::<usize>()?;
    if !(8 * 1024..=MAX_SUPPORTED_FRAME_SIZE).contains(&size) {
        bail!("fakehttp max frame size is out of range")
    }
    Ok(size)
}

/// Clamp a frame size into the supported fakehttp range.
///
/// # Parameters
///
/// * `size` - Requested frame size in bytes.
///
/// # Returns
///
/// Returns a frame size between 8 KiB and 64 KiB.
///
/// # Errors
///
/// This function does not return errors.
fn normalize_max_frame_size(size: usize) -> usize {
    size.clamp(8 * 1024, MAX_SUPPORTED_FRAME_SIZE)
}

/// Parse an HTTP authority into a target.
///
/// # Parameters
///
/// * `authority` - Authority string in `host:port` or `[ipv6]:port` form.
///
/// # Returns
///
/// Returns the parsed target.
///
/// # Errors
///
/// Returns an error when the authority is malformed or lacks a port.
fn parse_authority(authority: &str) -> Result<Target> {
    if authority.starts_with('[') {
        let closing = authority
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("invalid bracketed IPv6 fakehttp target"))?;
        let host = &authority[1..closing];
        let port = authority
            .get(closing + 1..)
            .and_then(|suffix| suffix.strip_prefix(':'))
            .ok_or_else(|| anyhow::anyhow!("fakehttp target is missing a port"))?
            .parse()?;
        return Ok(Target::new(host, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !host.contains(':') => {
            Ok(Target::new(host, port.parse()?))
        }
        _ => bail!("fakehttp target must be host:port"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fakehttp_target_path() {
        let target = URL_SAFE_NO_PAD.encode("example.com:443");
        let request = Request::parse(
            format!(
                "POST {FAKEHTTP_PATH_PREFIX}session/{target} HTTP/1.1\r\nContent-Encoding: {CRYPTO_ENCODING}\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("request");

        assert_eq!(
            request.target().expect("target"),
            Target::new("example.com", 443)
        );
        assert_eq!(request.session().expect("session"), "session");
        assert!(request.wants_crypto());
    }

    #[test]
    fn rejects_origin_form_scanner_probe() {
        assert!(Request::parse(b"GET / HTTP/1.0\r\n\r\n").is_err());
    }
}
