use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{Context as _, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::connector::{BoxStream, Connector, Target, relay};

const MAX_HEADER_SIZE: usize = 64 * 1024;
const MAX_FRAME_PLAINTEXT: usize = 16 * 1024;
const MAX_FRAME_CIPHERTEXT: usize = MAX_FRAME_PLAINTEXT + TAG_SIZE;
const TAG_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const SALT_SIZE: usize = 16;
const FRAME_HEADER_SIZE: usize = 4;
const FAKEHTTP_PATH_PREFIX: &str = "/api/v1/stream/";
const CRYPTO_ENCODING: &str = "aes-256-gcm";
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

pub async fn serve(
    mut client: BoxStream,
    connector: Arc<Connector>,
    aes_secret: Option<&str>,
) -> Result<()> {
    let header = read_header(&mut client).await?;
    let request = Request::parse(&header)?;
    let target = request.target()?;
    let session = request.session()?;
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

    client
        .write_all(
            b"HTTP/1.1 200 OK\r\n\
              Content-Type: application/octet-stream\r\n\
              Cache-Control: no-store\r\n\
              Connection: keep-alive\r\n\r\n",
        )
        .await?;
    let client = match crypto_secret {
        Some(secret) => encrypt_stream(client, secret, &session, CryptoRole::Server)?,
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
) -> Result<BoxStream> {
    let session = session_token(target);
    let request = request_header(endpoint, target, aes_secret.is_some(), &session);
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let header = read_header(&mut stream).await?;
    let status = std::str::from_utf8(&header)?
        .lines()
        .next()
        .unwrap_or_default();
    if !status.contains(" 200 ") {
        bail!("fakehttp upstream rejected tunnel: {status}")
    }
    match aes_secret {
        Some(secret) => encrypt_stream(stream, secret, &session, CryptoRole::Client),
        None => Ok(stream),
    }
}

fn request_header(endpoint: &Target, target: &Target, encrypted: bool, session: &str) -> String {
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
) -> Result<BoxStream> {
    Ok(Box::new(CryptoStream::new(stream, secret, session, role)?))
}

struct CryptoStream {
    inner: BoxStream,
    read_cipher: CipherDirection,
    write_cipher: CipherDirection,
    encrypted_in: Vec<u8>,
    plaintext_in: VecDeque<u8>,
    encrypted_out: VecDeque<u8>,
}

impl CryptoStream {
    fn new(inner: BoxStream, secret: &str, session: &str, role: CryptoRole) -> Result<Self> {
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
        Ok(Self {
            inner,
            read_cipher: CipherDirection::new(secret, session, read_label)?,
            write_cipher: CipherDirection::new(secret, session, write_label)?,
            encrypted_in: Vec::with_capacity(MAX_FRAME_CIPHERTEXT + FRAME_HEADER_SIZE),
            plaintext_in: VecDeque::with_capacity(MAX_FRAME_PLAINTEXT),
            encrypted_out: VecDeque::with_capacity(MAX_FRAME_CIPHERTEXT + FRAME_HEADER_SIZE),
        })
    }

    fn poll_flush_pending(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while !self.encrypted_out.is_empty() {
            let chunk_len = self.encrypted_out.len().min(8192);
            let chunk = self
                .encrypted_out
                .iter()
                .take(chunk_len)
                .copied()
                .collect::<Vec<_>>();
            let written = match Pin::new(&mut self.inner).poll_write(context, &chunk) {
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
            self.encrypted_out.drain(..written);
        }
        Poll::Ready(Ok(()))
    }

    fn try_decrypt_frame(&mut self) -> io::Result<bool> {
        if self.encrypted_in.len() < FRAME_HEADER_SIZE {
            return Ok(false);
        }
        let len = u32::from_be_bytes([
            self.encrypted_in[0],
            self.encrypted_in[1],
            self.encrypted_in[2],
            self.encrypted_in[3],
        ]) as usize;
        if !(TAG_SIZE..=MAX_FRAME_CIPHERTEXT).contains(&len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid fakehttp encrypted frame length",
            ));
        }
        let frame_len = FRAME_HEADER_SIZE + len;
        if self.encrypted_in.len() < frame_len {
            return Ok(false);
        }
        let ciphertext = self.encrypted_in[FRAME_HEADER_SIZE..frame_len].to_vec();
        self.encrypted_in.drain(..frame_len);
        let plaintext = self.read_cipher.decrypt(&ciphertext)?;
        self.plaintext_in.extend(plaintext);
        Ok(true)
    }

    fn queue_encrypted(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(MAX_FRAME_PLAINTEXT);
        let ciphertext = self.write_cipher.encrypt(&bytes[..count])?;
        let frame_len = u32::try_from(ciphertext.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "fakehttp encrypted frame is too large",
            )
        })?;
        self.encrypted_out.extend(frame_len.to_be_bytes());
        self.encrypted_out.extend(ciphertext);
        Ok(count)
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
            while buffer.remaining() > 0 {
                let Some(byte) = self.plaintext_in.pop_front() else {
                    break;
                };
                buffer.put_slice(&[byte]);
            }
            if buffer.filled().len() > filled_before {
                return Poll::Ready(Ok(()));
            }
            if self.try_decrypt_frame()? {
                continue;
            }

            let mut scratch = [0_u8; 8192];
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
        match self.as_mut().poll_flush_pending(context) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let accepted = match self.queue_encrypted(bytes) {
            Ok(accepted) => accepted,
            Err(error) => return Poll::Ready(Err(error)),
        };
        match self.as_mut().poll_flush_pending(context) {
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

    fn encrypt(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = self.next_nonce()?;
        self.cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fakehttp encryption failed"))
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = self.next_nonce()?;
        self.cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
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
        let mut client = encrypt_stream(Box::new(client), "secret", "session", CryptoRole::Client)
            .expect("client stream");
        let mut server = encrypt_stream(Box::new(server), "secret", "session", CryptoRole::Server)
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
}
