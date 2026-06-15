use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use anyhow::{Context as _, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::connector::{BoxStream, Connector, Target, relay};

const MAX_HEADER_SIZE: usize = 64 * 1024;
pub const DEFAULT_MAX_FRAME_SIZE: usize = 16 * 1024;
const MAX_SUPPORTED_FRAME_SIZE: usize = 64 * 1024;
const READ_CHUNK_SIZE: usize = 8192;
const MAX_PENDING_OUTPUT_FRAMES: usize = 4;
const TAG_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const SALT_SIZE: usize = 16;
const FRAME_HEADER_SIZE: usize = 4;
const FAKEHTTP_PATH_PREFIX: &str = "/api/v1/stream/";
const CRYPTO_ENCODING: &str = "aes-256-gcm";
const MAX_FRAME_SIZE_HEADER: &str = "X-Proxlet-Max-Frame-Size";
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

pub async fn serve(
    mut client: BoxStream,
    connector: Arc<Connector>,
    aes_secret: Option<&str>,
    max_frame_size: usize,
) -> Result<()> {
    let header = read_header(&mut client).await?;
    let request = Request::parse(&header)?;
    let target = request.target()?;
    let session = request.session()?;
    let negotiated_frame_size = request
        .max_frame_size()?
        .unwrap_or(DEFAULT_MAX_FRAME_SIZE)
        .min(normalize_max_frame_size(max_frame_size));
    let wants_crypto = request.wants_crypto();
    let crypto_secret = match (wants_crypto, aes_secret) {
        (true, Some(secret)) => Some(secret),
        (true, None) => {
            client
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            bail!("fakehttp client requested encryption but --aes-secret is not configured")
        }
        (false, Some(_)) => {
            client
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            bail!("fakehttp listener requires encrypted clients")
        }
        (false, None) => None,
    };

    let remote = match connector.connect(&target).await {
        Ok(remote) => remote,
        Err(error) => {
            client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Err(error);
        }
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/octet-stream\r\n\
         Cache-Control: no-store\r\n\
         {MAX_FRAME_SIZE_HEADER}: {negotiated_frame_size}\r\n\
         Connection: keep-alive\r\n\r\n",
    );
    client.write_all(response.as_bytes()).await?;
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
    relay(client, remote).await?;
    Ok(())
}

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
struct Request {
    path: String,
    headers: Vec<(String, String)>,
}

impl Request {
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

    fn target(&self) -> Result<Target> {
        let (_, token) = self.path_parts()?;
        let authority = String::from_utf8(URL_SAFE_NO_PAD.decode(token)?)?;
        parse_authority(&authority)
    }

    fn session(&self) -> Result<String> {
        let (session, _) = self.path_parts()?;
        if session.is_empty() {
            bail!("fakehttp session token is empty")
        }
        Ok(session.to_owned())
    }

    fn path_parts(&self) -> Result<(&str, &str)> {
        let suffix = self
            .path
            .strip_prefix(FAKEHTTP_PATH_PREFIX)
            .ok_or_else(|| anyhow::anyhow!("fakehttp request path is not supported"))?;
        suffix
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("fakehttp request path is missing session or target"))
    }

    fn wants_crypto(&self) -> bool {
        self.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("Content-Encoding")
                && value.eq_ignore_ascii_case(CRYPTO_ENCODING)
        })
    }

    fn max_frame_size(&self) -> Result<Option<usize>> {
        parse_max_frame_size_header(&self.headers)
    }
}

#[derive(Debug)]
struct Response {
    status: String,
    headers: Vec<(String, String)>,
}

impl Response {
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

    fn max_frame_size(&self) -> Result<Option<usize>> {
        parse_max_frame_size_header(&self.headers)
    }
}

fn parse_max_frame_size_header(headers: &[(String, String)]) -> Result<Option<usize>> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(MAX_FRAME_SIZE_HEADER))
        .map(|(_, value)| parse_max_frame_size(value))
        .transpose()
}

fn parse_max_frame_size(value: &str) -> Result<usize> {
    let size = value.parse::<usize>()?;
    if !(8 * 1024..=MAX_SUPPORTED_FRAME_SIZE).contains(&size) {
        bail!("fakehttp max frame size is out of range")
    }
    Ok(size)
}

fn normalize_max_frame_size(size: usize) -> usize {
    size.clamp(8 * 1024, MAX_SUPPORTED_FRAME_SIZE)
}

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

#[derive(Clone, Copy)]
pub enum CryptoRole {
    Client,
    Server,
}

fn encrypt_stream(
    stream: BoxStream,
    secret: &str,
    session: &str,
    role: CryptoRole,
    max_frame_size: usize,
) -> Result<BoxStream> {
    Ok(Box::new(CryptoStream::new(
        stream,
        secret,
        session,
        role,
        max_frame_size,
    )?))
}

struct CryptoStream {
    inner: BoxStream,
    read_cipher: CipherDirection,
    write_cipher: CipherDirection,
    max_frame_size: usize,
    encrypted_in: Vec<u8>,
    encrypted_in_start: usize,
    plaintext_in: Vec<u8>,
    plaintext_in_start: usize,
    encrypted_out: Vec<u8>,
    encrypted_out_start: usize,
}

impl CryptoStream {
    fn new(
        inner: BoxStream,
        secret: &str,
        session: &str,
        role: CryptoRole,
        max_frame_size: usize,
    ) -> Result<Self> {
        let (read_label, write_label) = match role {
            CryptoRole::Client => (
                b"server-to-client".as_slice(),
                b"client-to-server".as_slice(),
            ),
            CryptoRole::Server => (
                b"client-to-server".as_slice(),
                b"server-to-client".as_slice(),
            ),
        };
        let max_frame_size = normalize_max_frame_size(max_frame_size);
        Ok(Self {
            inner,
            read_cipher: CipherDirection::new(secret, session, read_label)?,
            write_cipher: CipherDirection::new(secret, session, write_label)?,
            max_frame_size,
            encrypted_in: Vec::with_capacity(max_frame_size + TAG_SIZE + FRAME_HEADER_SIZE),
            encrypted_in_start: 0,
            plaintext_in: Vec::with_capacity(max_frame_size),
            plaintext_in_start: 0,
            encrypted_out: Vec::with_capacity(max_frame_size + TAG_SIZE + FRAME_HEADER_SIZE),
            encrypted_out_start: 0,
        })
    }

    fn pending_encrypted_out(&self) -> usize {
        self.encrypted_out.len() - self.encrypted_out_start
    }

    fn poll_write_pending_once(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.encrypted_out_start >= self.encrypted_out.len() {
            self.compact_encrypted_out();
            return Poll::Ready(Ok(()));
        }
        let this = self.as_mut().get_mut();
        let pending = &this.encrypted_out[this.encrypted_out_start..];
        let written = match Pin::new(&mut this.inner).poll_write(context, pending) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "fakehttp encrypted stream write returned zero",
                )));
            }
            Poll::Ready(Ok(written)) => written,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        };
        self.encrypted_out_start += written;
        self.compact_encrypted_out();
        Poll::Ready(Ok(()))
    }

    fn poll_flush_pending(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.encrypted_out_start < self.encrypted_out.len() {
            match self.as_mut().poll_write_pending_once(context) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn try_decrypt_frame(&mut self) -> io::Result<bool> {
        let available = self.encrypted_in.len() - self.encrypted_in_start;
        if available < FRAME_HEADER_SIZE {
            return Ok(false);
        }
        let header_start = self.encrypted_in_start;
        let len = u32::from_be_bytes([
            self.encrypted_in[header_start],
            self.encrypted_in[header_start + 1],
            self.encrypted_in[header_start + 2],
            self.encrypted_in[header_start + 3],
        ]) as usize;
        if !(TAG_SIZE..=self.max_frame_size + TAG_SIZE).contains(&len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid fakehttp encrypted frame length",
            ));
        }
        let frame_len = FRAME_HEADER_SIZE + len;
        if available < frame_len {
            return Ok(false);
        }
        let ciphertext_start = header_start + FRAME_HEADER_SIZE;
        let frame_end = ciphertext_start + len;
        let plaintext_len = len - TAG_SIZE;
        {
            let frame = &mut self.encrypted_in[ciphertext_start..frame_end];
            let (ciphertext, tag_bytes) = frame.split_at_mut(plaintext_len);
            let tag = Tag::from_slice(tag_bytes);
            self.read_cipher.decrypt_in_place(ciphertext, tag)?;
        }
        self.plaintext_in.extend_from_slice(
            &self.encrypted_in[ciphertext_start..ciphertext_start + plaintext_len],
        );
        self.encrypted_in_start = frame_end;
        self.compact_encrypted_in();
        Ok(true)
    }

    fn queue_encrypted(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(self.max_frame_size);
        let frame_len = u32::try_from(count + TAG_SIZE).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "fakehttp encrypted frame is too large",
            )
        })?;
        self.encrypted_out.extend(frame_len.to_be_bytes());
        let plaintext_start = self.encrypted_out.len();
        self.encrypted_out.extend_from_slice(&bytes[..count]);
        let tag = self
            .write_cipher
            .encrypt_in_place(&mut self.encrypted_out[plaintext_start..plaintext_start + count])?;
        self.encrypted_out.extend_from_slice(&tag);
        Ok(count)
    }

    fn read_plaintext_into(&mut self, buffer: &mut ReadBuf<'_>) -> bool {
        if self.plaintext_in_start >= self.plaintext_in.len() {
            self.clear_plaintext_in();
            return false;
        }
        let available = &self.plaintext_in[self.plaintext_in_start..];
        let count = available.len().min(buffer.remaining());
        buffer.put_slice(&available[..count]);
        self.plaintext_in_start += count;
        self.clear_plaintext_in();
        count > 0
    }

    fn compact_encrypted_in(&mut self) {
        if self.encrypted_in_start == 0 {
            return;
        }
        if self.encrypted_in_start >= self.encrypted_in.len() {
            self.encrypted_in.clear();
            self.encrypted_in_start = 0;
        } else if self.encrypted_in_start >= self.max_frame_size {
            self.encrypted_in.drain(..self.encrypted_in_start);
            self.encrypted_in_start = 0;
        }
    }

    fn compact_encrypted_out(&mut self) {
        if self.encrypted_out_start == 0 {
            return;
        }
        if self.encrypted_out_start >= self.encrypted_out.len() {
            self.encrypted_out.clear();
            self.encrypted_out_start = 0;
        } else if self.encrypted_out_start >= self.max_frame_size {
            self.encrypted_out.drain(..self.encrypted_out_start);
            self.encrypted_out_start = 0;
        }
    }

    fn clear_plaintext_in(&mut self) {
        if self.plaintext_in_start >= self.plaintext_in.len() {
            self.plaintext_in.clear();
            self.plaintext_in_start = 0;
        }
    }
}

impl AsyncRead for CryptoStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled_before = buffer.filled().len();
        loop {
            self.read_plaintext_into(buffer);
            if buffer.filled().len() > filled_before {
                return Poll::Ready(Ok(()));
            }
            if self.try_decrypt_frame()? {
                continue;
            }

            let mut scratch = [0_u8; READ_CHUNK_SIZE];
            let mut read_buffer = ReadBuf::new(&mut scratch);
            let result = Pin::new(&mut self.inner).poll_read(context, &mut read_buffer);
            let filled = read_buffer.filled().len();
            match result {
                Poll::Ready(Ok(())) if filled == 0 => {
                    if self.encrypted_in.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "fakehttp encrypted frame ended early",
                    )));
                }
                Poll::Ready(Ok(())) => {
                    self.encrypted_in
                        .extend_from_slice(&read_buffer.filled()[..filled]);
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

impl AsyncWrite for CryptoStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.pending_encrypted_out()
            >= self.max_frame_size * MAX_PENDING_OUTPUT_FRAMES + TAG_SIZE
        {
            match self.as_mut().poll_flush_pending(context) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let accepted = match self.queue_encrypted(bytes) {
            Ok(accepted) => accepted,
            Err(error) => return Poll::Ready(Err(error)),
        };
        match self.as_mut().poll_write_pending_once(context) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(accepted)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush_pending(context) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(context),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush_pending(context) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(context),
            other => other,
        }
    }
}

struct CipherDirection {
    cipher: Aes256Gcm,
    base_nonce: [u8; NONCE_SIZE],
    counter: u64,
}

impl CipherDirection {
    fn new(secret: &str, session: &str, direction: &[u8]) -> Result<Self> {
        let salt = derive_salt(secret, session);
        let key = derive_key(secret, &salt);
        let base_nonce = derive_nonce(secret, session, &salt, direction);
        Ok(Self {
            cipher: Aes256Gcm::new_from_slice(&key)
                .context("could not initialize AES-256-GCM cipher")?,
            base_nonce,
            counter: 0,
        })
    }

    fn encrypt_in_place(&mut self, plaintext: &mut [u8]) -> io::Result<Tag> {
        let nonce = self.next_nonce()?;
        self.cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", plaintext)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fakehttp encryption failed"))
    }

    fn decrypt_in_place(&mut self, ciphertext: &mut [u8], tag: &Tag) -> io::Result<()> {
        let nonce = self.next_nonce()?;
        self.cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce), b"", ciphertext, tag)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fakehttp decryption failed"))
    }

    fn next_nonce(&mut self) -> io::Result<[u8; NONCE_SIZE]> {
        let counter = self.counter;
        self.counter = self.counter.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "fakehttp frame counter overflowed",
            )
        })?;
        let mut nonce = self.base_nonce;
        for (nonce_byte, counter_byte) in nonce[4..].iter_mut().zip(counter.to_be_bytes()) {
            *nonce_byte ^= counter_byte;
        }
        Ok(nonce)
    }
}

fn derive_salt(secret: &str, session: &str) -> [u8; SALT_SIZE] {
    let digest = Sha256::digest(
        [
            b"proxlet fakehttp salt\0".as_slice(),
            session.as_bytes(),
            secret.as_bytes(),
        ]
        .concat(),
    );
    let mut salt = [0_u8; SALT_SIZE];
    salt.copy_from_slice(&digest[..SALT_SIZE]);
    salt
}

fn derive_key(secret: &str, salt: &[u8; SALT_SIZE]) -> [u8; 32] {
    let digest = Sha256::digest(
        [
            b"proxlet fakehttp key\0".as_slice(),
            salt,
            secret.as_bytes(),
        ]
        .concat(),
    );
    let mut key = [0_u8; 32];
    key.copy_from_slice(&digest);
    key
}

fn derive_nonce(
    secret: &str,
    session: &str,
    salt: &[u8; SALT_SIZE],
    direction: &[u8],
) -> [u8; NONCE_SIZE] {
    let digest = Sha256::digest(
        [
            b"proxlet fakehttp nonce\0".as_slice(),
            salt,
            session.as_bytes(),
            direction,
            secret.as_bytes(),
        ]
        .concat(),
    );
    let mut nonce = [0_u8; NONCE_SIZE];
    nonce.copy_from_slice(&digest[..NONCE_SIZE]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    #[tokio::test]
    async fn encrypted_stream_round_trips() {
        let (client, server) = tokio::io::duplex(4096);
        let mut client = encrypt_stream(
            Box::new(client),
            "secret",
            "session",
            CryptoRole::Client,
            DEFAULT_MAX_FRAME_SIZE,
        )
        .expect("client stream");
        let mut server = encrypt_stream(
            Box::new(server),
            "secret",
            "session",
            CryptoRole::Server,
            DEFAULT_MAX_FRAME_SIZE,
        )
        .expect("server stream");

        client.write_all(b"hello").await.expect("client write");
        client.flush().await.expect("client flush");
        let mut input = [0_u8; 5];
        server.read_exact(&mut input).await.expect("server read");
        assert_eq!(&input, b"hello");

        server.write_all(b"world").await.expect("server write");
        server.flush().await.expect("server flush");
        let mut output = [0_u8; 5];
        client.read_exact(&mut output).await.expect("client read");
        assert_eq!(&output, b"world");
    }

    #[tokio::test]
    async fn encrypted_stream_round_trips_with_large_frame_size() {
        let (client, server) = tokio::io::duplex(128 * 1024);
        let mut client = encrypt_stream(
            Box::new(client),
            "secret",
            "session",
            CryptoRole::Client,
            64 * 1024,
        )
        .expect("client stream");
        let mut server = encrypt_stream(
            Box::new(server),
            "secret",
            "session",
            CryptoRole::Server,
            64 * 1024,
        )
        .expect("server stream");
        let input = vec![7_u8; 48 * 1024];

        client.write_all(&input).await.expect("client write");
        client.flush().await.expect("client flush");
        let mut output = vec![0_u8; input.len()];
        server.read_exact(&mut output).await.expect("server read");

        assert_eq!(output, input);
    }
}
