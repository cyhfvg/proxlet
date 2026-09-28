//! AES-GCM frame encryption for fakehttp streams.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::Tag;
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::connector::BoxStream;
use crate::fakehttp::SALT_SIZE;

use super::normalize_max_frame_size;

mod cipher;

use cipher::CipherDirection;

const READ_CHUNK_SIZE: usize = 8192;
const MAX_PENDING_OUTPUT_FRAMES: usize = 4;
const TAG_SIZE: usize = 16;
const FRAME_HEADER_SIZE: usize = 4;
const MAX_HELLO_FRAME_SIZE: usize = 512;

#[derive(Clone, Copy)]
/// Directional role used to select fakehttp read/write crypto labels.
pub enum CryptoRole {
    /// Downstream proxlet side of the tunnel.
    Client,
    /// Upstream proxlet side of the tunnel.
    Server,
}

/// Seal the encrypted hello frame carrying the tunnel target.
///
/// # Parameters
///
/// * `secret` - Shared AES secret.
/// * `client_nonce` - Random nonce chosen by the downstream client.
/// * `target_authority` - Target authority carried inside the hello frame.
/// * `aad` - Handshake transcript bound to the frame as additional
///   authenticated data.
///
/// # Returns
///
/// Returns the wire frame `len || ciphertext || tag`.
///
/// # Errors
///
/// Returns an error when AES-GCM initialization or encryption fails.
pub(super) fn seal_hello(
    secret: &str,
    client_nonce: &[u8; SALT_SIZE],
    target_authority: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let mut cipher = CipherDirection::handshake(secret, client_nonce)?;
    let mut payload = target_authority.to_vec();
    let tag = cipher.encrypt_in_place(&mut payload, aad)?;
    let frame_len = u32::try_from(payload.len() + TAG_SIZE)
        .map_err(|_| anyhow::anyhow!("fakehttp hello frame is too large"))?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len() + TAG_SIZE);
    frame.extend_from_slice(&frame_len.to_be_bytes());
    frame.extend_from_slice(&payload);
    frame.extend_from_slice(&tag);
    Ok(frame)
}

/// Open the encrypted hello frame and authenticate the handshake transcript.
///
/// # Parameters
///
/// * `secret` - Shared AES secret.
/// * `client_nonce` - Random nonce chosen by the downstream client.
/// * `frame` - Wire frame `len || ciphertext || tag` read from the hello chunk.
/// * `aad` - Handshake transcript bound to the frame as additional
///   authenticated data.
///
/// # Returns
///
/// Returns the authenticated target authority.
///
/// # Errors
///
/// Returns an error when the frame is malformed, decryption fails, or the
/// plaintext is not valid UTF-8.
pub(super) fn open_hello(
    secret: &str,
    client_nonce: &[u8; SALT_SIZE],
    frame: &[u8],
    aad: &[u8],
) -> Result<String> {
    if frame.len() < FRAME_HEADER_SIZE + TAG_SIZE {
        anyhow::bail!("fakehttp hello frame is too short");
    }
    let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if len < TAG_SIZE || frame.len() != FRAME_HEADER_SIZE + len {
        anyhow::bail!("fakehttp hello frame length mismatch");
    }
    let plaintext_len = len - TAG_SIZE;
    if plaintext_len > MAX_HELLO_FRAME_SIZE {
        anyhow::bail!("fakehttp hello frame is too large");
    }
    let mut payload = frame[FRAME_HEADER_SIZE..].to_vec();
    let (ciphertext, tag_bytes) = payload.split_at_mut(plaintext_len);
    let tag = Tag::from_slice(tag_bytes);
    let mut cipher = CipherDirection::handshake(secret, client_nonce)?;
    cipher
        .decrypt_in_place(ciphertext, tag, aad)
        .map_err(|_| anyhow::anyhow!("fakehttp hello frame failed authentication"))?;
    Ok(String::from_utf8(ciphertext.to_vec())?)
}

/// Wrap a stream in AES-GCM fakehttp frame encryption.
///
/// # Parameters
///
/// * `stream` - Plain stream to wrap.
/// * `secret` - Shared AES secret.
/// * `client_nonce` - Random nonce chosen by the downstream client.
/// * `server_salt` - Random salt chosen by the upstream server.
/// * `role` - Crypto role for read/write direction labels.
/// * `max_frame_size` - Maximum encrypted payload frame size.
///
/// # Returns
///
/// Returns a boxed stream that reads and writes plaintext.
///
/// # Errors
///
/// Returns an error when AES-GCM initialization fails.
pub(super) fn encrypt_stream(
    stream: BoxStream,
    secret: &str,
    client_nonce: &[u8; SALT_SIZE],
    server_salt: &[u8; SALT_SIZE],
    role: CryptoRole,
    max_frame_size: usize,
) -> Result<BoxStream> {
    Ok(Box::new(CryptoStream::new(
        stream,
        secret,
        client_nonce,
        server_salt,
        role,
        max_frame_size,
    )?))
}

/// Async stream adapter that encrypts writes and decrypts reads in fakehttp frames.
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
    /// Write bytes already queued but not yet reported as consumed.
    write_inflight: Option<usize>,
    /// Authenticated empty close frame has already been queued.
    close_frame_queued: bool,
    /// Clean EOF received via an empty authenticated close frame.
    closed: bool,
}

impl CryptoStream {
    /// Create a crypto stream with directional ciphers.
    ///
    /// # Parameters
    ///
    /// * `inner` - Underlying fakehttp byte stream.
    /// * `secret` - Shared AES secret.
    /// * `client_nonce` - Random nonce chosen by the downstream client.
    /// * `server_salt` - Random salt chosen by the upstream server.
    /// * `role` - Client or server role.
    /// * `max_frame_size` - Maximum frame payload size.
    ///
    /// # Returns
    ///
    /// Returns an initialized [`CryptoStream`].
    ///
    /// # Errors
    ///
    /// Returns an error when cipher initialization fails.
    fn new(
        inner: BoxStream,
        secret: &str,
        client_nonce: &[u8; SALT_SIZE],
        server_salt: &[u8; SALT_SIZE],
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
            read_cipher: CipherDirection::traffic(secret, client_nonce, server_salt, read_label)?,
            write_cipher: CipherDirection::traffic(secret, client_nonce, server_salt, write_label)?,
            max_frame_size,
            encrypted_in: Vec::with_capacity(max_frame_size + TAG_SIZE + FRAME_HEADER_SIZE),
            encrypted_in_start: 0,
            plaintext_in: Vec::with_capacity(max_frame_size),
            plaintext_in_start: 0,
            encrypted_out: Vec::with_capacity(max_frame_size + TAG_SIZE + FRAME_HEADER_SIZE),
            encrypted_out_start: 0,
            write_inflight: None,
            close_frame_queued: false,
            closed: false,
        })
    }

    /// Return the number of queued encrypted bytes waiting to be written.
    ///
    /// # Parameters
    ///
    /// * `self` - Crypto stream state.
    ///
    /// # Returns
    ///
    /// Returns the pending encrypted output byte count.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    fn pending_encrypted_out(&self) -> usize {
        self.encrypted_out.len() - self.encrypted_out_start
    }

    /// Try to write one pending encrypted output slice to the inner stream.
    ///
    /// # Parameters
    ///
    /// * `self` - Pinned crypto stream.
    /// * `context` - Async task context.
    ///
    /// # Returns
    ///
    /// Returns `Ready(Ok(()))` after one write attempt succeeds or no output is
    /// pending, `Pending` if the inner stream is not ready.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from the inner stream or `WriteZero` when the inner
    /// stream accepts zero bytes.
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

    /// Flush queued encrypted output into the inner stream.
    ///
    /// # Parameters
    ///
    /// * `self` - Pinned crypto stream.
    /// * `context` - Async task context.
    ///
    /// # Returns
    ///
    /// Returns `Ready(Ok(()))` when no queued encrypted output remains.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from pending writes.
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

    /// Decrypt one complete frame from the encrypted input buffer.
    ///
    /// # Parameters
    ///
    /// * `self` - Crypto stream state.
    ///
    /// # Returns
    ///
    /// Returns `true` when a frame was decrypted and queued as plaintext.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the frame length is invalid or decryption
    /// authentication fails.
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
            // Decrypt in place so the encrypted input allocation can be reused
            // across frames without allocating a fresh plaintext buffer.
            let frame = &mut self.encrypted_in[ciphertext_start..frame_end];
            let (ciphertext, tag_bytes) = frame.split_at_mut(plaintext_len);
            let tag = Tag::from_slice(tag_bytes);
            self.read_cipher.decrypt_in_place(ciphertext, tag, b"")?;
        }
        // An authenticated empty frame is the tunnel close signal; without it
        // a truncated stream is reported as an error instead of clean EOF.
        if plaintext_len == 0 {
            self.encrypted_in_start = frame_end;
            self.compact_encrypted_in();
            self.closed = true;
            return Ok(true);
        }
        self.plaintext_in.extend_from_slice(
            &self.encrypted_in[ciphertext_start..ciphertext_start + plaintext_len],
        );
        self.encrypted_in_start = frame_end;
        self.compact_encrypted_in();
        Ok(true)
    }

    /// Queue one encrypted frame for outbound plaintext bytes.
    ///
    /// # Parameters
    ///
    /// * `self` - Crypto stream state.
    /// * `bytes` - Plaintext bytes offered by the caller.
    ///
    /// # Returns
    ///
    /// Returns the number of plaintext bytes accepted into the frame.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when frame length conversion or encryption fails.
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
        // AES-GCM writes ciphertext over the queued plaintext and returns the
        // authentication tag separately, avoiding a per-frame output allocation.
        let tag = self.write_cipher.encrypt_in_place(
            &mut self.encrypted_out[plaintext_start..plaintext_start + count],
            b"",
        )?;
        self.encrypted_out.extend_from_slice(&tag);
        Ok(count)
    }

    /// Copy queued plaintext into a caller-provided read buffer.
    ///
    /// # Parameters
    ///
    /// * `self` - Crypto stream state.
    /// * `buffer` - Tokio read buffer to fill.
    ///
    /// # Returns
    ///
    /// Returns `true` when at least one byte was copied.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
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

    /// Compact or clear consumed encrypted input bytes.
    ///
    /// # Parameters
    ///
    /// * `self` - Crypto stream state.
    ///
    /// # Returns
    ///
    /// This function returns `()`.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
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

    /// Compact or clear consumed encrypted output bytes.
    ///
    /// # Parameters
    ///
    /// * `self` - Crypto stream state.
    ///
    /// # Returns
    ///
    /// This function returns `()`.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
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

    /// Clear the plaintext input buffer after all bytes are consumed.
    ///
    /// # Parameters
    ///
    /// * `self` - Crypto stream state.
    ///
    /// # Returns
    ///
    /// This function returns `()`.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    fn clear_plaintext_in(&mut self) {
        if self.plaintext_in_start >= self.plaintext_in.len() {
            self.plaintext_in.clear();
            self.plaintext_in_start = 0;
        }
    }
}

impl AsyncRead for CryptoStream {
    /// Poll for decrypted plaintext from the fakehttp stream.
    ///
    /// # Parameters
    ///
    /// * `self` - Pinned crypto stream.
    /// * `context` - Async task context.
    /// * `buffer` - Destination read buffer.
    ///
    /// # Returns
    ///
    /// Returns `Ready(Ok(()))` when bytes are available or EOF is reached, and
    /// `Pending` when the inner stream is not ready.
    ///
    /// # Errors
    ///
    /// Returns I/O errors, unexpected EOF for incomplete frames, or invalid-data
    /// errors for failed decryption.
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
                    // EOF without an authenticated close frame means the tunnel
                    // was truncated; only the empty close frame is clean EOF.
                    if self.closed {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "fakehttp encrypted stream ended without a close frame",
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
    /// Poll to encrypt and queue plaintext bytes.
    ///
    /// # Parameters
    ///
    /// * `self` - Pinned crypto stream.
    /// * `context` - Async task context.
    /// * `bytes` - Plaintext bytes to write.
    ///
    /// # Returns
    ///
    /// Returns the number of plaintext bytes accepted by the crypto stream.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from encryption or the inner stream.
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // A previous write was accepted into the user-space queue but the inner
        // write only partially completed; finish it before claiming more bytes.
        if let Some(accepted) = self.write_inflight.take() {
            match self.as_mut().poll_flush_pending(context) {
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(accepted)),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {
                    self.write_inflight = Some(accepted);
                    return Poll::Pending;
                }
            }
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
            // A short write leaves ciphertext queued. Do not report the
            // plaintext as accepted until that queue is drained.
            Poll::Pending => {
                self.write_inflight = Some(accepted);
                Poll::Pending
            }
            Poll::Ready(Ok(())) => match self.as_mut().poll_flush_pending(context) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(accepted)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => {
                    self.write_inflight = Some(accepted);
                    Poll::Pending
                }
            },
        }
    }

    /// Poll to flush all queued encrypted output.
    ///
    /// # Parameters
    ///
    /// * `self` - Pinned crypto stream.
    /// * `context` - Async task context.
    ///
    /// # Returns
    ///
    /// Returns `Ready(Ok(()))` when queued output and inner stream flush finish.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from pending writes or inner flush.
    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush_pending(context) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(context),
            other => other,
        }
    }

    /// Poll to flush queued frames and shut down the inner stream.
    ///
    /// # Parameters
    ///
    /// * `self` - Pinned crypto stream.
    /// * `context` - Async task context.
    ///
    /// # Returns
    ///
    /// Returns `Ready(Ok(()))` when shutdown completes.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from pending writes or inner shutdown.
    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Queue the authenticated close frame once. A second poll must not seal
        // another empty frame under the next nonce.
        if !self.close_frame_queued {
            match self.queue_encrypted(&[]) {
                Ok(_) => self.close_frame_queued = true,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        match self.as_mut().poll_flush_pending(context) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(context),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakehttp::DEFAULT_MAX_FRAME_SIZE;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn stream_pair(buffer: usize, frame_size: usize) -> (BoxStream, BoxStream) {
        let (client, server) = tokio::io::duplex(buffer);
        let nonce = [1_u8; SALT_SIZE];
        let salt = [2_u8; SALT_SIZE];
        let client = encrypt_stream(
            Box::new(client),
            "secret",
            &nonce,
            &salt,
            CryptoRole::Client,
            frame_size,
        )
        .expect("client stream");
        let server = encrypt_stream(
            Box::new(server),
            "secret",
            &nonce,
            &salt,
            CryptoRole::Server,
            frame_size,
        )
        .expect("server stream");
        (client, server)
    }

    #[tokio::test]
    async fn encrypted_stream_round_trips() {
        let (mut client, mut server) = stream_pair(4096, DEFAULT_MAX_FRAME_SIZE);

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
        let (mut client, mut server) = stream_pair(128 * 1024, 64 * 1024);
        let input = vec![7_u8; 48 * 1024];

        client.write_all(&input).await.expect("client write");
        client.flush().await.expect("client flush");
        let mut output = vec![0_u8; input.len()];
        server.read_exact(&mut output).await.expect("server read");

        assert_eq!(output, input);
    }

    #[tokio::test]
    async fn shutdown_delivers_clean_eof_to_the_peer() {
        let (mut client, mut server) = stream_pair(4096, DEFAULT_MAX_FRAME_SIZE);

        client.write_all(b"payload").await.expect("client write");
        client.shutdown().await.expect("client shutdown");

        let mut buffer = Vec::new();
        server.read_to_end(&mut buffer).await.expect("server read");
        assert_eq!(buffer, b"payload");
    }

    #[tokio::test]
    async fn truncation_without_close_frame_is_an_error() {
        let (client, server) = tokio::io::duplex(4096);
        let nonce = [1_u8; SALT_SIZE];
        let salt = [2_u8; SALT_SIZE];
        let mut writer = encrypt_stream(
            Box::new(client),
            "secret",
            &nonce,
            &salt,
            CryptoRole::Client,
            DEFAULT_MAX_FRAME_SIZE,
        )
        .expect("writer stream");
        let mut reader = encrypt_stream(
            Box::new(server),
            "secret",
            &nonce,
            &salt,
            CryptoRole::Server,
            DEFAULT_MAX_FRAME_SIZE,
        )
        .expect("reader stream");

        writer
            .write_all(b"truncated data")
            .await
            .expect("writer write");
        writer.flush().await.expect("writer flush");
        // Drop without shutdown: no authenticated close frame reaches the peer.
        drop(writer);

        let mut buffer = Vec::new();
        let result = reader.read_to_end(&mut buffer).await;
        let error = result.expect_err("truncation must surface an error");
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        // Buffered plaintext read before the truncation is still delivered.
        assert_eq!(buffer, b"truncated data");
    }
}
