//! Streaming TCE1 encryption/decryption over `futures::io::AsyncRead`, and
//! plaintext→ciphertext Range mapping.
//!
//! Each reader keeps two segment-sized buffers (2 × (64 KiB + 16 B), one being
//! filled, one being drained), allocated once. A
//! `DecryptReader` only yields a segment after it authenticates; an error part
//! way through means the object is corrupt or truncated, and a consumer must
//! abort (e.g. reset the HTTP response) rather than finish normally.

use super::envelope::{
    new_header, segment_offset, segment_plain_len, BlobIdentity, EnvelopeError, Header,
    SegmentCipher, SEGMENT_LEN, TAG_LEN,
};
use super::key::DataKey;
use crate::storage::{ByteRangeSpec, ResolvedByteRange};
use futures::io::AsyncRead;
use std::{
    io,
    pin::Pin,
    task::{ready, Context, Poll},
};

fn invalid(e: EnvelopeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

fn poisoned() -> io::Error {
    io::Error::other("TCE1 stream already failed")
}

/// Copies from `out[*pos..]` into `buf`.
fn drain(out: &[u8], pos: &mut usize, buf: &mut [u8]) -> usize {
    let n = (out.len() - *pos).min(buf.len());
    buf[..n].copy_from_slice(&out[*pos..*pos + n]);
    *pos += n;
    n
}

/// Reads one byte to check that `inner` is exhausted.
fn poll_eof<R: AsyncRead + Unpin>(inner: &mut R, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
    let mut probe = [0u8; 1];
    let n = ready!(Pin::new(inner).poll_read(cx, &mut probe))?;
    Poll::Ready(Ok(n == 0))
}

/// Reads into `seg[*filled..]` until full. `Ok(false)` means EOF came first.
fn poll_fill<R: AsyncRead + Unpin>(
    inner: &mut R,
    cx: &mut Context<'_>,
    seg: &mut [u8],
    filled: &mut usize,
) -> Poll<io::Result<bool>> {
    while *filled < seg.len() {
        let n = ready!(Pin::new(&mut *inner).poll_read(cx, &mut seg[*filled..]))?;
        if n == 0 {
            return Poll::Ready(Ok(false));
        }
        *filled += n;
    }
    Poll::Ready(Ok(true))
}

/// Turns a plaintext reader of a declared length into `header ‖ segments`.
/// Fails if the reader yields fewer or more bytes than declared. The final
/// segment is sealed only after the reader reports EOF, so over-long input
/// fails before a complete object has been yielded.
/// `R` must be `Unpin`; wrap with `Box::pin` if needed.
pub struct EncryptReader<R> {
    inner: R,
    cipher: SegmentCipher,
    plaintext_len: u64,
    segments: u64,
    next: u64,
    seg: Vec<u8>,
    filled: usize,
    filling: bool,
    out: Vec<u8>,
    out_pos: usize,
    failed: bool,
}

impl<R: AsyncRead + Unpin> EncryptReader<R> {
    pub fn new(
        key: &DataKey,
        id: &BlobIdentity<'_>,
        plaintext_len: u64,
        inner: R,
    ) -> Result<Self, EnvelopeError> {
        let header = new_header(key, plaintext_len)?;
        Ok(Self::from_header(key, id, &header, inner))
    }

    /// Test-only: a caller-chosen header reuses its salt, and so its per-blob
    /// key and nonces. Production always goes through [`Self::new`].
    #[cfg(test)]
    pub(crate) fn with_header(
        key: &DataKey,
        id: &BlobIdentity<'_>,
        header: &Header,
        inner: R,
    ) -> Self {
        Self::from_header(key, id, header, inner)
    }

    fn from_header(key: &DataKey, id: &BlobIdentity<'_>, header: &Header, inner: R) -> Self {
        Self {
            inner,
            cipher: SegmentCipher::new(key, id, header),
            plaintext_len: header.plaintext_len(),
            segments: header.segment_count(),
            next: 0,
            seg: Vec::with_capacity(SEGMENT_LEN + TAG_LEN),
            filled: 0,
            filling: false,
            out: header.as_bytes().to_vec(),
            out_pos: 0,
            failed: false,
        }
    }

    fn step(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        loop {
            if self.out_pos < self.out.len() {
                return Poll::Ready(Ok(drain(&self.out, &mut self.out_pos, buf)));
            }
            if self.next == self.segments {
                return Poll::Ready(Ok(0));
            }
            if !self.filling {
                self.seg.clear();
                self.seg
                    .resize(segment_plain_len(self.plaintext_len, self.next), 0);
                self.filled = 0;
                self.filling = true;
            }
            if !ready!(poll_fill(
                &mut self.inner,
                cx,
                &mut self.seg,
                &mut self.filled
            ))? {
                return Poll::Ready(Err(invalid(EnvelopeError::LengthMismatch)));
            }
            // Check for over-long input before releasing the final segment.
            if self.next + 1 == self.segments && !ready!(poll_eof(&mut self.inner, cx))? {
                return Poll::Ready(Err(invalid(EnvelopeError::LengthMismatch)));
            }
            let tag = self.cipher.seal_segment(self.next, &mut self.seg);
            self.seg.extend_from_slice(&tag);
            std::mem::swap(&mut self.seg, &mut self.out);
            self.out_pos = 0;
            self.next += 1;
            self.filling = false;
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for EncryptReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(poisoned()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let r = this.step(cx, buf);
        if matches!(r, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        r
    }
}

/// The ciphertext span and trimming for a plaintext byte range of one blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentRange {
    plaintext_len: u64,
    start: u64,
    end: u64,
    first: u64,
    last: u64,
}

impl SegmentRange {
    /// First ciphertext byte to fetch (absolute, inclusive).
    pub fn ciphertext_start(&self) -> u64 {
        segment_offset(self.first)
    }

    /// Last ciphertext byte to fetch (absolute, inclusive).
    pub fn ciphertext_end(&self) -> u64 {
        segment_offset(self.last)
            + (segment_plain_len(self.plaintext_len, self.last) + TAG_LEN) as u64
            - 1
    }

    /// The plaintext range that will be yielded, for `Content-Range`.
    pub fn plaintext_range(&self) -> ResolvedByteRange {
        ByteRangeSpec::Inclusive {
            start: self.start,
            end: self.end,
        }
        .resolve(self.plaintext_len)
        .expect("constructed from a satisfiable range")
    }

    /// Total plaintext size of the blob, for `Content-Range` and 416.
    pub fn total_size(&self) -> u64 {
        self.plaintext_len
    }
}

impl Header {
    /// Maps a requested plaintext range onto whole segments. `None` means the
    /// range is unsatisfiable against the plaintext length (answer 416 with
    /// [`Header::plaintext_len`] as the total).
    pub fn map_range(&self, spec: ByteRangeSpec) -> Option<SegmentRange> {
        let r = spec.resolve(self.plaintext_len())?;
        let seg = SEGMENT_LEN as u64;
        Some(SegmentRange {
            plaintext_len: self.plaintext_len(),
            start: r.start(),
            end: r.end(),
            first: r.start() / seg,
            last: r.end() / seg,
        })
    }
}

/// Turns TCE1 ciphertext into authenticated plaintext, one segment at a time.
/// `R` must be `Unpin`; wrap with `Box::pin` if needed.
pub struct DecryptReader<R> {
    inner: R,
    cipher: SegmentCipher,
    plaintext_len: u64,
    next: u64,
    last: u64,
    skip: usize,
    remaining: u64,
    seg: Vec<u8>,
    filled: usize,
    filling: bool,
    out: Vec<u8>,
    out_pos: usize,
    finished: bool,
    failed: bool,
}

impl<R: AsyncRead + Unpin> DecryptReader<R> {
    /// Whole object. `inner` is positioned just after the header.
    pub fn new(
        key: &DataKey,
        id: &BlobIdentity<'_>,
        header: &Header,
        inner: R,
    ) -> Result<Self, EnvelopeError> {
        let p = header.plaintext_len();
        Self::build(key, id, header, inner, 0, header.segment_count() - 1, 0, p)
    }

    /// A plaintext range. `inner` yields exactly the bytes
    /// `range.ciphertext_start()..=range.ciphertext_end()` of the object.
    /// Refused if `range` was mapped for a different plaintext length (the
    /// mapping depends on nothing else in the header).
    pub fn range(
        key: &DataKey,
        id: &BlobIdentity<'_>,
        header: &Header,
        range: SegmentRange,
        inner: R,
    ) -> Result<Self, EnvelopeError> {
        if range.plaintext_len != header.plaintext_len() {
            return Err(EnvelopeError::Header(
                "range was mapped for another plaintext length",
            ));
        }
        let skip = (range.start - range.first * SEGMENT_LEN as u64) as usize;
        let len = range.end - range.start + 1;
        Self::build(key, id, header, inner, range.first, range.last, skip, len)
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        key: &DataKey,
        id: &BlobIdentity<'_>,
        header: &Header,
        inner: R,
        first: u64,
        last: u64,
        skip: usize,
        remaining: u64,
    ) -> Result<Self, EnvelopeError> {
        if header.dek_id() != key.id() {
            return Err(EnvelopeError::KeyMismatch);
        }
        Ok(Self {
            inner,
            cipher: SegmentCipher::new(key, id, header),
            plaintext_len: header.plaintext_len(),
            next: first,
            last,
            skip,
            remaining,
            seg: Vec::with_capacity(SEGMENT_LEN + TAG_LEN),
            filled: 0,
            filling: false,
            out: Vec::with_capacity(SEGMENT_LEN + TAG_LEN),
            out_pos: 0,
            finished: false,
            failed: false,
        })
    }

    fn step(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        loop {
            if self.out_pos < self.out.len() {
                return Poll::Ready(Ok(drain(&self.out, &mut self.out_pos, buf)));
            }
            if self.next > self.last {
                if !self.finished {
                    if !ready!(poll_eof(&mut self.inner, cx))? {
                        return Poll::Ready(Err(invalid(EnvelopeError::Integrity)));
                    }
                    self.finished = true;
                }
                return Poll::Ready(Ok(0));
            }
            let len = segment_plain_len(self.plaintext_len, self.next);
            if !self.filling {
                self.seg.clear();
                self.seg.resize(len + TAG_LEN, 0);
                self.filled = 0;
                self.filling = true;
            }
            if !ready!(poll_fill(
                &mut self.inner,
                cx,
                &mut self.seg,
                &mut self.filled
            ))? {
                return Poll::Ready(Err(invalid(EnvelopeError::Integrity)));
            }
            let (body, tag) = self.seg.split_at_mut(len);
            self.cipher
                .open_segment(self.next, body, tag)
                .map_err(invalid)?;
            let start = self.skip;
            let end = len
                .min(start.saturating_add(usize::try_from(self.remaining).unwrap_or(usize::MAX)));
            self.seg.truncate(end);
            std::mem::swap(&mut self.seg, &mut self.out);
            self.out_pos = start;
            self.skip = 0;
            self.remaining -= (end - start) as u64;
            self.next += 1;
            self.filling = false;
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for DecryptReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(poisoned()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let r = this.step(cx, buf);
        if matches!(r, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        r
    }
}
