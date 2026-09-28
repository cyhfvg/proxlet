//! Block reads that return only the requested prefix.
//!
//! Header parsers used to read one byte at a time so a later body byte could
//! not be consumed early. These helpers read in blocks, then put bytes after
//! the marker back onto the same [`BoxStream`].

use std::io::{Cursor, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::connector::BoxStream;

const READ_CHUNK: usize = 1024;

/// Read until `marker`, then unread any bytes past it.
///
/// # Parameters
///
/// * `stream` - Stream to read. Bytes after `marker` are pushed back onto it.
/// * `initial` - Bytes already consumed. They belong to the returned buffer,
///   not to the unread tail.
/// * `marker` - Terminator included in the returned buffer.
/// * `limit` - Maximum accepted end position of `marker`, in bytes.
/// * `what` - Lowercase label used in the size-limit error.
///
/// # Returns
///
/// Returns the bytes from the start of `initial` through the end of `marker`.
/// A marker that ends exactly at `limit` is accepted.
///
/// # Errors
///
/// Returns an error when `marker` ends past `limit`, the stream ends before
/// `marker`, or I/O fails. The failed read is not unread; the caller closes
/// the connection.
///
/// # Examples
///
/// ```ignore
/// let header = read_until(&mut stream, &[], b"\r\n\r\n", 64 * 1024, "HTTP header").await?;
/// ```
pub(crate) async fn read_until(
    stream: &mut BoxStream,
    initial: &[u8],
    marker: &[u8],
    limit: usize,
    what: &str,
) -> Result<Vec<u8>> {
    let mut buf = initial.to_vec();
    loop {
        if let Some(end) = find_marker(&buf, marker) {
            // 先找 marker 再检查长度, 这样块读越过 limit 时, 结束位置仍在 limit 内的 marker 仍然合法.
            if end > limit {
                bail!("{what} exceeds {limit} bytes");
            }
            let tail = buf.split_off(end);
            unread(stream, &tail);
            return Ok(buf);
        }
        if buf.len() >= limit {
            bail!("{what} exceeds {limit} bytes");
        }
        let mut chunk = [0_u8; READ_CHUNK];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "early eof").into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Push `bytes` so the next read on `stream` yields them first.
///
/// # Parameters
///
/// * `stream` - Stream that should replay `bytes` before its current contents.
/// * `bytes` - Bytes to replay. An empty slice leaves `stream` unchanged.
///
/// # Returns
///
/// This function does not return a value.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// unread(&mut stream, b"TUNNEL");
/// ```
pub(crate) fn unread(stream: &mut BoxStream, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    // Cursor 同时实现 AsyncRead 和 AsyncWrite, 才能在替换期间占住 BoxStream.
    // 后续 unread 会再包一层, 所以最新前缀先被读到.
    let inner = std::mem::replace(stream, Box::new(Cursor::new(Vec::new())));
    *stream = Box::new(Prefixed {
        prefix: Cursor::new(bytes.to_vec()),
        inner,
    });
}

/// Locate `marker` and return the index just past it.
///
/// # Parameters
///
/// * `buf` - Bytes already read.
/// * `marker` - Terminator to find. An empty marker matches at the start.
///
/// # Returns
///
/// Returns the index just past `marker`, or `None` when it is absent.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let end = find_marker(b"AB\r\n\r\nCD", b"\r\n\r\n");
/// ```
fn find_marker(buf: &[u8], marker: &[u8]) -> Option<usize> {
    if marker.is_empty() {
        return Some(0);
    }
    buf.windows(marker.len())
        .position(|window| window == marker)
        .map(|start| start + marker.len())
}

/// Stream that yields a prefix before delegating to an inner stream.
struct Prefixed {
    prefix: Cursor<Vec<u8>>,
    inner: BoxStream,
}

impl AsyncRead for Prefixed {
    /// Poll the unread prefix, then the inner stream.
    ///
    /// # Parameters
    ///
    /// * `self` - Prefixed stream.
    /// * `cx` - Polling context.
    /// * `buf` - Destination buffer.
    ///
    /// # Returns
    ///
    /// Returns ready when prefix bytes were copied or the inner stream is
    /// ready.
    ///
    /// # Errors
    ///
    /// Returns inner-stream I/O errors. The prefix itself does not fail.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let start = self.prefix.position() as usize;
        let available = &self.prefix.get_ref()[start..];
        if !available.is_empty() {
            let n = available.len().min(buf.remaining());
            if n == 0 {
                return Poll::Ready(Ok(()));
            }
            buf.put_slice(&available[..n]);
            self.prefix.set_position((start + n) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Prefixed {
    /// Write to the inner stream, never to the unread prefix.
    ///
    /// # Parameters
    ///
    /// * `self` - Prefixed stream.
    /// * `cx` - Polling context.
    /// * `buf` - Bytes to write.
    ///
    /// # Returns
    ///
    /// Returns the inner stream's write poll.
    ///
    /// # Errors
    ///
    /// Returns inner-stream I/O errors.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    /// Flush the inner stream.
    ///
    /// # Parameters
    ///
    /// * `self` - Prefixed stream.
    /// * `cx` - Polling context.
    ///
    /// # Returns
    ///
    /// Returns the inner stream's flush poll.
    ///
    /// # Errors
    ///
    /// Returns inner-stream I/O errors.
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    /// Shut down the inner stream.
    ///
    /// # Parameters
    ///
    /// * `self` - Prefixed stream.
    /// * `cx` - Polling context.
    ///
    /// # Returns
    ///
    /// Returns the inner stream's shutdown poll.
    ///
    /// # Errors
    ///
    /// Returns inner-stream I/O errors.
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn read_until_returns_bytes_after_the_marker() {
        let (client, mut server) = tokio::io::duplex(8);
        let reader = tokio::spawn(async move {
            let mut stream: BoxStream = Box::new(client);
            let header = read_until(&mut stream, &[], b"\r\n\r\n", 64, "header")
                .await
                .expect("header");
            let mut rest = [0_u8; 6];
            stream.read_exact(&mut rest).await.expect("remainder");
            (header, rest)
        });
        server
            .write_all(b"HTTP/1.1 200 OK\r\n\r\nTUNNEL")
            .await
            .unwrap();
        drop(server);
        let (header, rest) = reader.await.unwrap();
        assert_eq!(header, b"HTTP/1.1 200 OK\r\n\r\n");
        assert_eq!(&rest, b"TUNNEL");
    }

    #[tokio::test]
    async fn read_until_keeps_initial_bytes_in_the_header() {
        let (client, mut server) = tokio::io::duplex(64);
        server
            .write_all(b"TTP/1.1 200 OK\r\n\r\nTUNNEL")
            .await
            .unwrap();
        drop(server);
        let mut stream: BoxStream = Box::new(client);
        let header = read_until(&mut stream, b"H", b"\r\n\r\n", 64, "header")
            .await
            .expect("header");
        let mut rest = [0_u8; 6];
        stream.read_exact(&mut rest).await.expect("remainder");
        assert_eq!(header, b"HTTP/1.1 200 OK\r\n\r\n");
        assert_eq!(&rest, b"TUNNEL");
    }

    #[tokio::test]
    async fn read_until_accepts_a_marker_that_ends_on_the_limit() {
        let (client, mut server) = tokio::io::duplex(16);
        server.write_all(b"AB\r\n\r\n").await.unwrap();
        drop(server);
        let mut stream: BoxStream = Box::new(client);
        let header = read_until(&mut stream, &[], b"\r\n\r\n", 6, "header")
            .await
            .expect("exact limit");
        assert_eq!(header, b"AB\r\n\r\n");
    }

    #[tokio::test]
    async fn read_until_rejects_a_marker_past_the_limit() {
        let (client, mut server) = tokio::io::duplex(16);
        server.write_all(b"ABCDEF\r\n\r\n").await.unwrap();
        drop(server);
        let mut stream: BoxStream = Box::new(client);
        let error = read_until(&mut stream, &[], b"\r\n\r\n", 6, "header")
            .await
            .expect_err("past limit");
        assert!(error.to_string().contains("exceeds"));
    }
}
