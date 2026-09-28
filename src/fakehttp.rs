//! fakehttp proxlet-to-proxlet transport implementation.
//!
//! fakehttp wraps arbitrary proxy traffic in HTTP-looking requests and
//! responses. The v2 handshake keeps the URL path constant and carries the
//! tunnel target inside the first body chunk. When an AES secret is
//! configured, that hello frame is AES-256-GCM encrypted and authenticated
//! over the full handshake transcript (method, path, Host, frame size,
//! encoding), so an on-path attacker cannot redirect the tunnel by rewriting
//! the request. The client contributes a random nonce and the server answers
//! with a random salt; both feed key derivation, which makes replayed
//! handshakes fail and prevents GCM nonce reuse across sessions.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::{LazyLock, Mutex};

use anyhow::{Context as _, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::camouflage;
use crate::connector::{BoxStream, Connector, Target, relay};

mod chunked;
mod crypto;

use chunked::chunked_body_stream;
pub use crypto::CryptoRole;
use crypto::{encrypt_stream, open_hello, seal_hello};

const MAX_HEADER_SIZE: usize = 64 * 1024;
/// Default fakehttp encrypted frame payload size in bytes.
pub const DEFAULT_MAX_FRAME_SIZE: usize = 16 * 1024;
const MAX_SUPPORTED_FRAME_SIZE: usize = 64 * 1024;
const SALT_SIZE: usize = 16;
const HELLO_TAG_SIZE: usize = 16;
const HELLO_HEADER_SIZE: usize = 4;
/// Largest accepted hello frame payload: the target authority (max 255 bytes
/// of host plus port text) plus the AES-GCM tag.
const MAX_HELLO_PAYLOAD: usize = 512 + HELLO_TAG_SIZE;
/// Fixed fakehttp request path; the tunnel target is not in the URL.
const FAKEHTTP_PATH: &str = "/api/v1/stream";
const CRYPTO_ENCODING: &str = "aes-256-gcm";
const MAX_FRAME_SIZE_HEADER: &str = "X-Proxlet-Max-Frame-Size";
const NONCE_HEADER: &str = "X-Proxlet-Nonce";
const SALT_HEADER: &str = "X-Proxlet-Salt";
const MAX_REMEMBERED_NONCES: usize = 4096;

type NonceLru = Mutex<(VecDeque<[u8; SALT_SIZE]>, HashSet<[u8; SALT_SIZE]>)>;

/// Recently seen client nonces used to reject replayed handshakes.
static SEEN_NONCES: LazyLock<NonceLru> =
    LazyLock::new(|| Mutex::new((VecDeque::new(), HashSet::new())));

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
/// Returns an error when the fakehttp request is invalid, encryption policy
/// does not match, the hello frame fails authentication, the client nonce was
/// replayed, target connection fails, HTTP response writing fails, or
/// relaying traffic fails.
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
    // The frame-size header is mandatory: silently falling back to a default
    // lets a middlebox strip it and desynchronize the two frame sizes.
    let request_frame_size = match request.max_frame_size() {
        Ok(Some(size)) => size,
        Ok(None) => {
            camouflage::write_not_found(&mut client).await?;
            bail!("fakehttp request is missing the {MAX_FRAME_SIZE_HEADER} header")
        }
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
    // The client nonce is only meaningful for encrypted tunnels, where it
    // feeds key derivation and replay rejection.
    let client_nonce = match crypto_secret {
        Some(_) => match request.nonce() {
            Ok(nonce) => nonce,
            Err(_) => {
                camouflage::write_not_found(&mut client).await?;
                return Ok(());
            }
        },
        None => [0_u8; SALT_SIZE],
    };
    let negotiated_frame_size = request_frame_size.min(normalize_max_frame_size(max_frame_size));
    let host = request.host().to_owned();

    // Read the first body chunk on the raw stream: the response header must
    // later be written outside the chunked framing, so the stream stays raw
    // until the handshake is accepted.
    let hello = match read_hello_chunk(&mut client).await {
        Ok(hello) => hello,
        Err(_) => {
            let _ = camouflage::write_not_found(&mut client).await;
            return Ok(());
        }
    };
    // Read and authenticate the hello frame before dialing anything: without
    // proof of the shared secret the server must not open connections to
    // arbitrary hosts (P1-12), and the target must be bound to the
    // authenticated handshake transcript (P0-1).
    let target = match crypto_secret {
        Some(secret) => {
            let aad = handshake_aad(&host, request_frame_size, true);
            let authority = match open_hello(secret, &client_nonce, &hello, &aad) {
                Ok(authority) => authority,
                Err(_) => {
                    camouflage::write_not_found(&mut client).await?;
                    bail!("fakehttp hello frame failed authentication")
                }
            };
            if is_replayed_nonce(&client_nonce) {
                camouflage::write_not_found(&mut client).await?;
                bail!("fakehttp client nonce was replayed")
            }
            parse_authority(&authority)?
        }
        None => {
            let authority = match std::str::from_utf8(&hello[HELLO_HEADER_SIZE..]) {
                Ok(authority) => authority,
                Err(_) => {
                    let _ = camouflage::write_not_found(&mut client).await;
                    return Ok(());
                }
            };
            parse_authority(authority)?
        }
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

    // The server salt is fresh per connection: replaying a captured request
    // cannot reproduce an earlier (key, nonce) pair (P1-11).
    let server_salt = match crypto_secret {
        Some(_) => random_salt()?,
        None => [0_u8; SALT_SIZE],
    };
    let mut response = format!(
        "HTTP/1.1 200 OK\r\n\
         Server: nginx\r\n\
         Content-Type: application/octet-stream\r\n\
         Transfer-Encoding: chunked\r\n\
         Cache-Control: no-store\r\n\
         {MAX_FRAME_SIZE_HEADER}: {negotiated_frame_size}\r\n",
    );
    if crypto_secret.is_some() {
        let salt_token = URL_SAFE_NO_PAD.encode(server_salt);
        response.push_str(&format!("{SALT_HEADER}: {salt_token}\r\n"));
    }
    response.push_str("Connection: keep-alive\r\n\r\n");
    client.write_all(response.as_bytes()).await?;
    client.flush().await?;
    let body = chunked_body_stream(client);
    let body = match crypto_secret {
        Some(secret) => encrypt_stream(
            body,
            secret,
            &client_nonce,
            &server_salt,
            CryptoRole::Server,
            negotiated_frame_size,
        )?,
        None => body,
    };
    // After the HTTP handshake, both directions become raw tunneled streams.
    relay(body, remote).await?;
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
/// Returns an error when request writing, the authenticated hello frame,
/// fakehttp response parsing, or crypto stream initialization fails.
pub async fn connect(
    mut stream: BoxStream,
    endpoint: &Target,
    target: &Target,
    aes_secret: Option<&str>,
    max_frame_size: usize,
) -> Result<BoxStream> {
    let max_frame_size = normalize_max_frame_size(max_frame_size);
    let encrypted = aes_secret.is_some();
    let client_nonce = match aes_secret {
        Some(_) => random_salt()?,
        None => [0_u8; SALT_SIZE],
    };
    let request = request_header(endpoint, encrypted, &client_nonce, max_frame_size);
    stream.write_all(request.as_bytes()).await?;
    // The hello chunk carries the target: encrypted and transcript-bound when
    // a secret is configured, plain length-prefixed bytes otherwise.
    let hello = match aes_secret {
        Some(secret) => {
            let aad = handshake_aad(&endpoint.authority(), max_frame_size, true);
            seal_hello(secret, &client_nonce, target.authority().as_bytes(), &aad)?
        }
        None => plaintext_hello(target),
    };
    write_hello_chunk(&mut stream, &hello).await?;
    stream.flush().await?;
    let header = read_header(&mut stream).await?;
    let response = Response::parse(&header)?;
    if response.status_code()? != 200 {
        bail!("fakehttp upstream rejected tunnel: {}", response.status)
    }
    if response.has_body() {
        bail!("fakehttp upstream returned a 200 response with a body");
    }
    let negotiated_frame_size = response
        .max_frame_size()?
        .ok_or_else(|| anyhow::anyhow!("fakehttp response is missing the frame size header"))?;
    if negotiated_frame_size > max_frame_size {
        bail!(
            "fakehttp response frame size {negotiated_frame_size} exceeds the requested \
             {max_frame_size}"
        );
    }
    let server_salt = match aes_secret {
        Some(_) => response.salt()?,
        None => [0_u8; SALT_SIZE],
    };
    let stream = chunked_body_stream(stream);
    match aes_secret {
        Some(secret) => encrypt_stream(
            stream,
            secret,
            &client_nonce,
            &server_salt,
            CryptoRole::Client,
            negotiated_frame_size,
        ),
        None => Ok(stream),
    }
}

/// Build the plain length-prefixed hello frame for unencrypted tunnels.
///
/// # Parameters
///
/// * `target` - Final destination requested by the local client.
///
/// # Returns
///
/// Returns the wire frame `len || authority`.
///
/// # Errors
///
/// This function does not return errors.
fn plaintext_hello(target: &Target) -> Vec<u8> {
    let authority = target.authority();
    let mut frame = Vec::with_capacity(HELLO_HEADER_SIZE + authority.len());
    let len = u32::try_from(authority.len()).unwrap_or(u32::MAX);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(authority.as_bytes());
    frame
}

/// Write one raw HTTP chunk carrying the hello frame.
///
/// # Parameters
///
/// * `stream` - Raw upstream stream after the request header was written.
/// * `frame` - Encoded hello frame bytes.
///
/// # Returns
///
/// Returns `Ok(())` after the chunk is written.
///
/// # Errors
///
/// Returns an error when writing to the stream fails.
async fn write_hello_chunk(stream: &mut BoxStream, frame: &[u8]) -> Result<()> {
    let mut size_line = [0_u8; 20];
    let size_text = format_hex_size(frame.len(), &mut size_line);
    stream.write_all(size_text).await?;
    stream.write_all(b"\r\n").await?;
    stream.write_all(frame).await?;
    stream.write_all(b"\r\n").await?;
    Ok(())
}

/// Format a byte count as uppercase hexadecimal digits.
///
/// # Parameters
///
/// * `size` - Byte count to format.
/// * `buffer` - Scratch buffer receiving the digits.
///
/// # Returns
///
/// Returns the formatted digit slice.
///
/// # Errors
///
/// This function does not return errors.
fn format_hex_size<'a>(size: usize, buffer: &'a mut [u8; 20]) -> &'a mut [u8] {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut start = buffer.len();
    let mut value = size;
    loop {
        start -= 1;
        buffer[start] = HEX[value % 16];
        value /= 16;
        if value == 0 {
            break;
        }
    }
    &mut buffer[start..]
}

/// Build the authenticated-data transcript binding a hello frame.
///
/// # Parameters
///
/// * `host` - Host header value seen by both endpoints.
/// * `frame_size` - Frame size offered in the request header.
/// * `encrypted` - Whether the tunnel advertises AES-256-GCM encoding.
///
/// # Returns
///
/// Returns the AAD bytes covering the handshake fields.
///
/// # Errors
///
/// This function does not return errors.
fn handshake_aad(host: &str, frame_size: usize, encrypted: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(host.len() + 32);
    aad.extend_from_slice(b"proxlet fakehttp v2");
    aad.push(0);
    aad.extend_from_slice(host.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&frame_size.to_be_bytes());
    aad.push(u8::from(encrypted));
    aad
}

/// Generate a random 128-bit value used as a client nonce or server salt.
///
/// # Parameters
///
/// This function takes no parameters.
///
/// # Returns
///
/// Returns a fresh random value.
///
/// # Errors
///
/// Returns an error when the system random source fails.
fn random_salt() -> Result<[u8; SALT_SIZE]> {
    let mut value = [0_u8; SALT_SIZE];
    getrandom::fill(&mut value).context("could not generate fakehttp random value")?;
    Ok(value)
}

/// Record a client nonce and report whether it was already seen.
///
/// # Parameters
///
/// * `nonce` - Client nonce from an authenticated hello frame.
///
/// # Returns
///
/// Returns `true` when the nonce was replayed.
///
/// # Errors
///
/// This function does not return errors.
fn is_replayed_nonce(nonce: &[u8; SALT_SIZE]) -> bool {
    let mut guard = SEEN_NONCES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !guard.1.insert(*nonce) {
        return true;
    }
    guard.0.push_back(*nonce);
    while guard.0.len() > MAX_REMEMBERED_NONCES {
        match guard.0.pop_front() {
            Some(evicted) => {
                guard.1.remove(&evicted);
            }
            None => break,
        }
    }
    false
}

/// Build the HTTP request header used to open a fakehttp tunnel.
///
/// # Parameters
///
/// * `endpoint` - Upstream fakehttp endpoint.
/// * `encrypted` - Whether to advertise AES-256-GCM frame encoding.
/// * `client_nonce` - Random nonce contributed by this client.
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
    encrypted: bool,
    client_nonce: &[u8; SALT_SIZE],
    max_frame_size: usize,
) -> String {
    let mut request = format!(
        "POST {FAKEHTTP_PATH} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: Mozilla/5.0\r\n\
         Accept: */*\r\n\
         Content-Type: application/octet-stream\r\n\
         Transfer-Encoding: chunked\r\n\
         Cache-Control: no-cache\r\n\
         {MAX_FRAME_SIZE_HEADER}: {max_frame_size}\r\n",
        endpoint.authority()
    );
    if encrypted {
        let nonce_token = URL_SAFE_NO_PAD.encode(client_nonce);
        request.push_str(&format!(
            "Content-Encoding: {CRYPTO_ENCODING}\r\n{NONCE_HEADER}: {nonce_token}\r\n"
        ));
    }
    request.push_str("Connection: keep-alive\r\n\r\n");
    request
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

/// Read the first HTTP chunk carrying the tunnel hello frame from a raw stream.
///
/// # Parameters
///
/// * `stream` - Raw upstream stream positioned at the start of the body.
///
/// # Returns
///
/// Returns the raw hello frame bytes (`len || payload`).
///
/// # Errors
///
/// Returns an error when the chunk size line is invalid, the declared frame
/// length is out of range, the trailing delimiter is missing, or the stream
/// ends before the chunk completes.
async fn read_hello_chunk(stream: &mut BoxStream) -> Result<Vec<u8>> {
    // Read the size line byte by byte so following chunk bytes stay buffered
    // in the kernel for the chunked reader that takes over later.
    let mut line = Vec::with_capacity(16);
    loop {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await?;
        line.push(byte[0]);
        if line.len() > 64 {
            bail!("fakehttp hello chunk size line is too long");
        }
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            break;
        }
    }
    let text = std::str::from_utf8(&line)?;
    let chunk_size = usize::from_str_radix(text, 16)
        .with_context(|| format!("invalid fakehttp hello chunk size: {text}"))?;
    if !(HELLO_HEADER_SIZE + 1..=HELLO_HEADER_SIZE + MAX_HELLO_PAYLOAD).contains(&chunk_size) {
        bail!("invalid fakehttp hello frame length");
    }
    let mut frame = vec![0_u8; chunk_size];
    stream.read_exact(&mut frame).await?;
    let mut delimiter = [0_u8; 2];
    stream.read_exact(&mut delimiter).await?;
    if &delimiter != b"\r\n" {
        bail!("invalid fakehttp hello chunk delimiter");
    }
    let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if len + HELLO_HEADER_SIZE != chunk_size {
        bail!("fakehttp hello frame length does not match its chunk");
    }
    Ok(frame)
}

#[derive(Debug)]
/// Parsed inbound fakehttp HTTP request.
struct Request {
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
    /// Returns a parsed [`Request`] for POST requests on the fixed stream
    /// path.
    ///
    /// # Errors
    ///
    /// Returns an error when the header is not UTF-8, lacks a valid request
    /// line, uses another method or path, or contains malformed header lines.
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
        if !method.eq_ignore_ascii_case("POST")
            || path != FAKEHTTP_PATH
            || !version.starts_with("HTTP/")
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
        Ok(Self { headers })
    }

    /// Return the Host header value.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed fakehttp request.
    ///
    /// # Returns
    ///
    /// Returns the Host header value, or an empty string when absent.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    fn host(&self) -> &str {
        self.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Host"))
            .map(|(_, value)| value.as_str())
            .unwrap_or_default()
    }

    /// Decode the client nonce from the request header.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed fakehttp request.
    ///
    /// # Returns
    ///
    /// Returns the decoded 128-bit client nonce.
    ///
    /// # Errors
    ///
    /// Returns an error when the header is missing, malformed, or not 16
    /// bytes after decoding.
    fn nonce(&self) -> Result<[u8; SALT_SIZE]> {
        let value = self
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(NONCE_HEADER))
            .map(|(_, value)| value)
            .ok_or_else(|| anyhow::anyhow!("fakehttp request is missing {NONCE_HEADER}"))?;
        let decoded = URL_SAFE_NO_PAD.decode(value)?;
        decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("fakehttp client nonce must be 16 bytes"))
    }

    /// Check whether the request asks for AES-256-GCM payload encoding.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed fakehttp request.
    ///
    /// # Returns
    ///
    /// Returns `true` when `Content-Encoding` matches the fakehttp crypto
    /// value.
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
    /// Returns an error when the frame size header is not numeric or is
    /// outside the supported range.
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
    /// Returns an error when the response is not UTF-8, lacks a status line,
    /// or contains malformed header lines.
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

    /// Parse the numeric status code from the status line.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed fakehttp response.
    ///
    /// # Returns
    ///
    /// Returns the three-digit status code.
    ///
    /// # Errors
    ///
    /// Returns an error when the status line is not a valid HTTP status line.
    fn status_code(&self) -> Result<u16> {
        let mut parts = self.status.split(' ');
        let version = parts.next().unwrap_or_default();
        if !version.starts_with("HTTP/") {
            bail!("invalid fakehttp response status line");
        }
        let code = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("fakehttp response status line has no code"))?;
        code.parse::<u16>()
            .with_context(|| format!("invalid fakehttp response status code: {code}"))
    }

    /// Check whether the response declares a non-empty body.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed fakehttp response.
    ///
    /// # Returns
    ///
    /// Returns `true` when `Content-Length` is greater than zero. A chunked
    /// tunnel body is expected and does not count.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    fn has_body(&self) -> bool {
        self.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("Content-Length")
                && value.trim().parse::<usize>().is_ok_and(|length| length > 0)
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
    /// Returns an error when the frame size header is not numeric or is
    /// outside the supported range.
    fn max_frame_size(&self) -> Result<Option<usize>> {
        parse_max_frame_size_header(&self.headers)
    }

    /// Decode the server salt from the response header.
    ///
    /// # Parameters
    ///
    /// * `self` - Parsed fakehttp response.
    ///
    /// # Returns
    ///
    /// Returns the decoded 128-bit server salt.
    ///
    /// # Errors
    ///
    /// Returns an error when the header is missing, malformed, or not 16
    /// bytes after decoding.
    fn salt(&self) -> Result<[u8; SALT_SIZE]> {
        let value = self
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(SALT_HEADER))
            .map(|(_, value)| value)
            .ok_or_else(|| anyhow::anyhow!("fakehttp response is missing {SALT_HEADER}"))?;
        let decoded = URL_SAFE_NO_PAD.decode(value)?;
        decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("fakehttp server salt must be 16 bytes"))
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
    fn parses_stream_request_headers() {
        let nonce = URL_SAFE_NO_PAD.encode([7_u8; SALT_SIZE]);
        let request = Request::parse(
            format!(
                "POST {FAKEHTTP_PATH} HTTP/1.1\r\n\
                 Host: proxy.example:8080\r\n\
                 Content-Encoding: {CRYPTO_ENCODING}\r\n\
                 {NONCE_HEADER}: {nonce}\r\n\
                 {MAX_FRAME_SIZE_HEADER}: 16384\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("request");

        assert_eq!(request.host(), "proxy.example:8080");
        assert_eq!(request.nonce().expect("nonce"), [7_u8; SALT_SIZE]);
        assert_eq!(request.max_frame_size().expect("size"), Some(16 * 1024));
        assert!(request.wants_crypto());
    }

    #[test]
    fn rejects_origin_form_scanner_probe() {
        assert!(Request::parse(b"GET / HTTP/1.0\r\n\r\n").is_err());
    }

    #[test]
    fn rejects_requests_without_frame_size_header() {
        let request =
            Request::parse(format!("POST {FAKEHTTP_PATH} HTTP/1.1\r\nHost: h\r\n\r\n").as_bytes())
                .expect("request");

        assert_eq!(request.max_frame_size().expect("size"), None);
    }

    #[test]
    fn hello_frame_binds_target_to_handshake_transcript() {
        let nonce = [3_u8; SALT_SIZE];
        let aad = handshake_aad("proxy.example:8080", 16 * 1024, true);
        let frame = seal_hello("secret", &nonce, b"example.com:443", &aad).expect("seal");

        let authority = open_hello("secret", &nonce, &frame, &aad).expect("open");
        assert_eq!(authority, "example.com:443");

        // A rewritten Host or frame size must break authentication.
        let tampered_aad = handshake_aad("evil.example:8080", 16 * 1024, true);
        assert!(open_hello("secret", &nonce, &frame, &tampered_aad).is_err());
        // A wrong secret must fail before any target is revealed.
        assert!(open_hello("other", &nonce, &frame, &aad).is_err());
    }

    #[test]
    fn replayed_nonce_is_detected() {
        let first = [11_u8; SALT_SIZE];
        let second = [12_u8; SALT_SIZE];

        assert!(!is_replayed_nonce(&first));
        assert!(is_replayed_nonce(&first));
        assert!(!is_replayed_nonce(&second));
    }

    #[test]
    fn response_status_and_body_checks() {
        let response =
            Response::parse(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").expect("response");

        assert_eq!(response.status_code().expect("code"), 200);
        assert!(!response.has_body());

        let with_body =
            Response::parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n").expect("response");
        assert!(with_body.has_body());
    }
}
