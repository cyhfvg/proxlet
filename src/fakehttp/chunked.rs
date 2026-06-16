//! HTTP/1.1 chunked body adapter for fakehttp streams.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::connector::BoxStream;

const MAX_CHUNK_SIZE_LINE: usize = 64;
const READ_CHUNK_SIZE: usize = 8192;

/// Wrap a stream so reads and writes operate on HTTP chunk payload bytes.
pub(super) fn chunked_body_stream(stream: BoxStream) -> BoxStream {
    Box::new(ChunkedBodyStream::new(stream))
}

enum ReadState {
    SizeLine(Vec<u8>),
    Data(usize),
    DataCrlf(usize),
    Done,
}

struct ChunkedBodyStream {
    inner: BoxStream,
    read_state: ReadState,
    write_out: Vec<u8>,
    write_out_start: usize,
    shutdown_chunk_queued: bool,
}

impl ChunkedBodyStream {
    fn new(inner: BoxStream) -> Self {
        Self {
            inner,
            read_state: ReadState::SizeLine(Vec::with_capacity(16)),
            write_out: Vec::with_capacity(READ_CHUNK_SIZE + 16),
            write_out_start: 0,
            shutdown_chunk_queued: false,
        }
    }

    fn pending_write_out(&self) -> usize {
        self.write_out.len() - self.write_out_start
    }

    fn compact_write_out(&mut self) {
        if self.write_out_start == 0 {
            return;
        }
        if self.write_out_start >= self.write_out.len() {
            self.write_out.clear();
            self.write_out_start = 0;
        }
    }

    fn poll_write_pending_once(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.write_out_start >= self.write_out.len() {
            self.compact_write_out();
            return Poll::Ready(Ok(()));
        }

        let this = self.as_mut().get_mut();
        let pending = &this.write_out[this.write_out_start..];
        let written = match Pin::new(&mut this.inner).poll_write(context, pending) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "chunked body stream write returned zero",
                )));
            }
            Poll::Ready(Ok(written)) => written,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        };
        self.write_out_start += written;
        self.compact_write_out();
        Poll::Ready(Ok(()))
    }

    fn poll_flush_pending(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.write_out_start < self.write_out.len() {
            match self.as_mut().poll_write_pending_once(context) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn queue_chunk(&mut self, bytes: &[u8]) -> usize {
        let count = bytes.len().min(READ_CHUNK_SIZE);
        self.write_out.extend(format!("{count:X}\r\n").as_bytes());
        self.write_out.extend_from_slice(&bytes[..count]);
        self.write_out.extend_from_slice(b"\r\n");
        count
    }

    fn queue_shutdown_chunk(&mut self) {
        if !self.shutdown_chunk_queued {
            self.write_out.extend_from_slice(b"0\r\n\r\n");
            self.shutdown_chunk_queued = true;
        }
    }

    fn poll_read_byte(
        &mut self,
        context: &mut Context<'_>,
        description: &'static str,
    ) -> Poll<io::Result<u8>> {
        let mut byte = [0_u8; 1];
        let mut read_buffer = ReadBuf::new(&mut byte);
        match Pin::new(&mut self.inner).poll_read(context, &mut read_buffer) {
            Poll::Ready(Ok(())) if read_buffer.filled().is_empty() => Poll::Ready(Err(
                io::Error::new(io::ErrorKind::UnexpectedEof, description),
            )),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(byte[0])),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn parse_chunk_size(line: &[u8]) -> io::Result<usize> {
        let text = std::str::from_utf8(line).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "chunk size line is not utf-8")
        })?;
        let size = text.split_once(';').map_or(text, |(size, _)| size).trim();
        usize::from_str_radix(size, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))
    }
}

impl AsyncRead for ChunkedBodyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled_before = buffer.filled().len();
        loop {
            let state = std::mem::replace(&mut self.read_state, ReadState::Done);
            match state {
                ReadState::SizeLine(mut line) => {
                    let byte = match self
                        .as_mut()
                        .get_mut()
                        .poll_read_byte(context, "chunked body ended while reading chunk size")
                    {
                        Poll::Ready(Ok(byte)) => byte,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => {
                            self.read_state = ReadState::SizeLine(line);
                            return Poll::Pending;
                        }
                    };

                    line.push(byte);
                    if line.len() > MAX_CHUNK_SIZE_LINE {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "chunk size line is too long",
                        )));
                    }
                    if line.ends_with(b"\r\n") {
                        line.truncate(line.len() - 2);
                        let size = Self::parse_chunk_size(&line)?;
                        self.read_state = if size == 0 {
                            ReadState::Done
                        } else {
                            ReadState::Data(size)
                        };
                    } else {
                        self.read_state = ReadState::SizeLine(line);
                    }
                }
                ReadState::Data(mut remaining) => {
                    if remaining == 0 {
                        self.read_state = ReadState::DataCrlf(0);
                        continue;
                    }
                    if buffer.remaining() == 0 {
                        self.read_state = ReadState::Data(remaining);
                        return Poll::Ready(Ok(()));
                    }

                    let mut scratch = [0_u8; READ_CHUNK_SIZE];
                    let count = remaining.min(buffer.remaining()).min(scratch.len());
                    let mut read_buffer = ReadBuf::new(&mut scratch[..count]);
                    match Pin::new(&mut self.inner).poll_read(context, &mut read_buffer) {
                        Poll::Ready(Ok(())) if read_buffer.filled().is_empty() => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "chunked body ended while reading chunk data",
                            )));
                        }
                        Poll::Ready(Ok(())) => {
                            let filled = read_buffer.filled();
                            remaining -= filled.len();
                            buffer.put_slice(filled);
                            self.read_state = ReadState::Data(remaining);
                            if buffer.filled().len() > filled_before {
                                return Poll::Ready(Ok(()));
                            }
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => {
                            self.read_state = ReadState::Data(remaining);
                            return Poll::Pending;
                        }
                    }
                }
                ReadState::DataCrlf(mut offset) => {
                    let byte = match self
                        .as_mut()
                        .get_mut()
                        .poll_read_byte(context, "chunked body ended while reading chunk delimiter")
                    {
                        Poll::Ready(Ok(byte)) => byte,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => {
                            self.read_state = ReadState::DataCrlf(offset);
                            return Poll::Pending;
                        }
                    };
                    let expected = if offset == 0 { b'\r' } else { b'\n' };
                    if byte != expected {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid chunk delimiter",
                        )));
                    }
                    offset += 1;
                    if offset == 2 {
                        self.read_state = ReadState::SizeLine(Vec::with_capacity(16));
                    } else {
                        self.read_state = ReadState::DataCrlf(offset);
                    }
                }
                ReadState::Done => {
                    self.read_state = ReadState::Done;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for ChunkedBodyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.pending_write_out() > 0 {
            match self.as_mut().poll_flush_pending(context) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let accepted = self.queue_chunk(bytes);
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
        if self.pending_write_out() == 0 {
            self.queue_shutdown_chunk();
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn chunked_body_stream_round_trips_payloads() {
        let (left, right) = tokio::io::duplex(4096);
        let mut left = chunked_body_stream(Box::new(left));
        let mut right = chunked_body_stream(Box::new(right));

        left.write_all(b"hello").await.expect("left write");
        left.flush().await.expect("left flush");
        let mut input = [0_u8; 5];
        right.read_exact(&mut input).await.expect("right read");
        assert_eq!(&input, b"hello");

        right.write_all(b"world").await.expect("right write");
        right.flush().await.expect("right flush");
        let mut output = [0_u8; 5];
        left.read_exact(&mut output).await.expect("left read");
        assert_eq!(&output, b"world");
    }
}
