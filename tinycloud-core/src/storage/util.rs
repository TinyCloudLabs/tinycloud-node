use crate::hash::{Blake3Hasher, Hash};
use core::pin::Pin;
use futures::{
    io::AsyncWrite,
    task::{Context, Poll},
};
use pin_project::pin_project;
use std::io::Error as IoError;

#[pin_project]
#[derive(Debug)]
pub struct HashBuffer<B> {
    #[pin]
    buffer: B,
    hasher: Blake3Hasher,
}

impl<B> HashBuffer<B> {
    pub fn into_inner(self) -> (Blake3Hasher, B) {
        (self.hasher, self.buffer)
    }
    pub fn hasher(&self) -> &Blake3Hasher {
        &self.hasher
    }
    pub fn hash(&mut self) -> Hash {
        self.hasher.finalize()
    }
}

impl<B> HashBuffer<B> {
    pub fn new(buffer: B) -> Self {
        Self {
            buffer,
            hasher: Blake3Hasher::new(),
        }
    }
}

impl<B> AsyncWrite for HashBuffer<B>
where
    B: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        let p = self.project();
        match p.buffer.poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                p.hasher.update(&buf[..written]);
                Poll::Ready(Ok(written))
            }
            result => result,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        self.project().buffer.poll_flush(cx)
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        self.project().buffer.poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::HashBuffer;
    use futures::{
        io::{AsyncWrite, AsyncWriteExt, BufReader},
        task::{Context, Poll},
    };
    use std::{io, pin::Pin};

    #[derive(Debug, Default)]
    struct HostileWriter {
        bytes: Vec<u8>,
        calls: usize,
    }

    impl AsyncWrite for HostileWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.calls += 1;
            if this.calls.is_multiple_of(3) {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            let written = buf.len().min(7);
            this.bytes.extend_from_slice(&buf[..written]);
            Poll::Ready(Ok(written))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn hashes_only_bytes_accepted_by_inner_writer() {
        let data: Vec<_> = (0..16_384).map(|index| (index % 251) as u8).collect();

        let mut expected = HashBuffer::new(Vec::new());
        expected.write_all(&data).await.unwrap();
        let expected_hash = expected.hash();

        for capacity in [1, 17, 4096, 1024 * 1024] {
            let mut buffered = HashBuffer::new(HostileWriter::default());
            futures::io::copy_buf(
                BufReader::with_capacity(capacity, data.as_slice()),
                &mut buffered,
            )
            .await
            .unwrap();
            let hash = buffered.hash();
            let (_, writer) = buffered.into_inner();

            assert_eq!(writer.bytes, data, "buffer capacity: {capacity}");
            assert_eq!(hash, expected_hash, "buffer capacity: {capacity}");
        }
    }
}

#[pin_project]
#[derive(Debug)]
pub struct Content<R> {
    size: u64,
    #[pin]
    content: R,
}

impl<R> Content<R> {
    pub fn new(size: u64, content: R) -> Self {
        Self { size, content }
    }

    pub fn len(&self) -> u64 {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn into_inner(self) -> (u64, R) {
        (self.size, self.content)
    }
}

impl<R> futures::io::AsyncRead for Content<R>
where
    R: futures::io::AsyncRead,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.project();
        this.content.poll_read(cx, buf)
    }

    fn poll_read_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.project();
        this.content.poll_read_vectored(cx, bufs)
    }
}
