//! TCE1 envelope tests: known-answer vectors from an independent Python
//! implementation (`testdata/gen_vectors.py`), round-trip/stream/range
//! properties, and rejection of tampered, truncated, reordered, swapped or
//! misbound ciphertext.

use super::envelope::{seal_with_header, segment_offset, Header};
use super::stream::{DecryptReader, EncryptReader};
use super::*;
use crate::hash::{hash, Hash};
use crate::storage::ByteRangeSpec;
use futures::io::{AsyncRead, AsyncReadExt};
use proptest::prelude::*;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

const SEG: usize = SEGMENT_LEN;
const SPACE: &str = "tinycloud:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266:default";

fn key(id: u32, fill: u8) -> DataKey {
    DataKey::new(DekId::new(id), [fill; 32])
}

fn bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn kv(h: &Hash) -> BlobIdentity<'_> {
    BlobIdentity::KvBlock {
        space: SPACE,
        content_hash: h,
    }
}

/// Splits reads into caller-chosen sizes and returns `Pending` before every
/// other read, to exercise resumption.
struct Chunked {
    data: Vec<u8>,
    pos: usize,
    sizes: Vec<usize>,
    calls: usize,
}

impl Chunked {
    fn new(data: Vec<u8>, sizes: Vec<usize>) -> Self {
        Self {
            data,
            pos: 0,
            sizes,
            calls: 0,
        }
    }
}

impl AsyncRead for Chunked {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.calls += 1;
        if self.calls.is_multiple_of(2) {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let want = self.sizes[self.calls % self.sizes.len()].max(1);
        let n = want.min(buf.len()).min(self.data.len() - self.pos);
        let pos = self.pos;
        buf[..n].copy_from_slice(&self.data[pos..pos + n]);
        self.pos += n;
        Poll::Ready(Ok(n))
    }
}

/// Reads to the end with caller buffers of varying size.
fn read_all<R: AsyncRead + Unpin>(mut r: R, bufs: &[usize]) -> io::Result<Vec<u8>> {
    futures::executor::block_on(async {
        let mut out = Vec::new();
        let mut i = 0;
        loop {
            let mut buf = vec![0u8; bufs[i % bufs.len()].max(1)];
            i += 1;
            let n = r.read(&mut buf).await?;
            if n == 0 {
                return Ok(out);
            }
            out.extend_from_slice(&buf[..n]);
        }
    })
}

fn stream_open(k: &DataKey, id: &BlobIdentity<'_>, ct: &[u8]) -> io::Result<Vec<u8>> {
    let header = Header::parse(ct).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let r = DecryptReader::new(
        k,
        id,
        &header,
        Chunked::new(ct[HEADER_LEN..].to_vec(), vec![4093]),
    )
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    read_all(r, &[8192])
}

fn is_integrity(r: io::Result<Vec<u8>>) -> bool {
    match r {
        Err(e) => e
            .get_ref()
            .and_then(|i| i.downcast_ref::<EnvelopeError>())
            .is_some_and(|e| matches!(e, EnvelopeError::Integrity)),
        Ok(_) => false,
    }
}

fn segment(p: usize, i: usize) -> std::ops::Range<usize> {
    let off = segment_offset(i as u64) as usize;
    let len = (p - i * SEG).min(SEG) + TAG_LEN;
    off..off + len
}

// ---------- known-answer vectors ----------

#[derive(serde::Deserialize)]
struct Vectors {
    vectors: Vec<Vector>,
    object_names: Vec<NameVector>,
}

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    dek: String,
    dek_id: u32,
    salt: String,
    identity: serde_json::Value,
    plaintext: serde_json::Value,
    ciphertext_len: u64,
    ciphertext_sha256: String,
    ciphertext: Option<String>,
    ciphertext_head: Option<String>,
}

#[derive(serde::Deserialize)]
struct NameVector {
    nk: String,
    space: String,
    content_hash: String,
    space_tag: String,
    object_name: String,
}

fn arr32(h: &str) -> [u8; 32] {
    hex::decode(h).unwrap().try_into().unwrap()
}

fn s<'a>(v: &'a serde_json::Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}

#[test]
fn known_answer_vectors_match_independent_reference() {
    use sha2::{Digest, Sha256};
    let v: Vectors = serde_json::from_str(include_str!("testdata/vectors.json")).unwrap();
    assert_eq!(v.vectors.len(), 8);
    for t in &v.vectors {
        let k = DataKey::new(DekId::new(t.dek_id), arr32(&t.dek));
        let pt = match t.plaintext.get("hex") {
            Some(h) => hex::decode(h.as_str().unwrap()).unwrap(),
            None => (0..t.plaintext["pattern_len"].as_u64().unwrap())
                .map(|i| (i % 251) as u8)
                .collect(),
        };
        let i = &t.identity;
        let content_hash;
        let id = match s(i, "purpose") {
            "kv-block" => {
                content_hash = Hash::try_from(hex::decode(s(i, "content_hash")).unwrap()).unwrap();
                BlobIdentity::KvBlock {
                    space: s(i, "space"),
                    content_hash: &content_hash,
                }
            }
            "sql-checkpoint" => BlobIdentity::SqlCheckpoint {
                service: s(i, "service"),
                space: s(i, "space"),
                name: s(i, "name"),
                checkpoint_content_hash: s(i, "checkpoint_content_hash"),
                checkpoint_size_bytes: i["checkpoint_size_bytes"].as_u64().unwrap(),
            },
            "sql-wal" => BlobIdentity::SqlWal {
                service: s(i, "service"),
                space: s(i, "space"),
                name: s(i, "name"),
                revision: i["revision"].as_i64().unwrap(),
                checkpoint_content_hash: s(i, "checkpoint_content_hash"),
                delta_content_hash: s(i, "delta_content_hash"),
            },
            p => panic!("unknown purpose {p}"),
        };
        let header = Header::build(k.id(), pt.len() as u64, &arr32(&t.salt));

        let ct = seal_with_header(&k, &id, &header, pt.clone());
        assert_eq!(ct.len() as u64, t.ciphertext_len, "{}", t.name);
        assert_eq!(
            hex::encode(Sha256::digest(&ct)),
            t.ciphertext_sha256,
            "{}",
            t.name
        );
        if let Some(full) = &t.ciphertext {
            assert_eq!(&hex::encode(&ct), full, "{}", t.name);
        }
        if let Some(head) = &t.ciphertext_head {
            assert!(hex::encode(&ct).starts_with(head), "{}", t.name);
        }

        let streamed = read_all(
            EncryptReader::with_header(&k, &id, &header, Chunked::new(pt.clone(), vec![777])),
            &[1000],
        )
        .unwrap();
        assert_eq!(streamed, ct, "{} streaming", t.name);
        assert_eq!(open(&k, &id, ct.clone()).unwrap(), pt, "{}", t.name);
        assert_eq!(stream_open(&k, &id, &ct).unwrap(), pt, "{}", t.name);
    }

    for n in &v.object_names {
        let nk = ObjectNameKey::new(arr32(&n.nk));
        let h = Hash::try_from(hex::decode(&n.content_hash).unwrap()).unwrap();
        assert_eq!(space_tag(&nk, &n.space), n.space_tag);
        assert_eq!(sealed_object_name(&nk, &n.space, &h), n.object_name);
    }
}

// ---------- round trip, streaming, sizes ----------

fn edge_len() -> impl Strategy<Value = usize> {
    prop_oneof![
        (0usize..4, -1i64..=1).prop_map(|(k, d)| (k as i64 * SEG as i64 + d).max(0) as usize),
        0usize..(3 * SEG + 100),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn seal_open_round_trip(len in edge_len(), seed: u64) {
        let k = key(1, 9);
        let h = hash(b"x");
        let pt = bytes(len, seed);
        let ct = seal(&k, &kv(&h), pt.clone()).unwrap();
        prop_assert_eq!(ct.len() as u64, ciphertext_len(len as u64).unwrap());
        prop_assert_eq!(plaintext_len(ct.len() as u64), Some(len as u64));
        prop_assert_eq!(Header::parse(&ct).unwrap().plaintext_len(), len as u64);
        prop_assert_eq!(open(&k, &kv(&h), ct).unwrap(), pt);
    }

    #[test]
    fn streaming_matches_whole_buffer(
        len in edge_len(),
        seed: u64,
        sizes in prop::collection::vec(1usize..70_000, 1..6),
        bufs in prop::collection::vec(1usize..70_000, 1..6),
    ) {
        let k = key(2, 3);
        let h = hash(b"y");
        let pt = bytes(len, seed);
        let header = Header::build(k.id(), len as u64, &[seed as u8; 32]);
        let whole = seal_with_header(&k, &kv(&h), &header, pt.clone());
        let enc = EncryptReader::with_header(&k, &kv(&h), &header, Chunked::new(pt.clone(), sizes.clone()));
        prop_assert_eq!(&read_all(enc, &bufs).unwrap(), &whole);
        let dec = DecryptReader::new(&k, &kv(&h), &header, Chunked::new(whole[HEADER_LEN..].to_vec(), sizes)).unwrap();
        prop_assert_eq!(read_all(dec, &bufs).unwrap(), pt);
    }

    #[test]
    fn length_inverse(p in 0u64..(1u64 << 44), c in 0u64..(1u64 << 44)) {
        prop_assert_eq!(plaintext_len(ciphertext_len(p).unwrap()), Some(p));
        if let Some(q) = plaintext_len(c) {
            prop_assert_eq!(ciphertext_len(q).unwrap(), c);
        }
    }

    #[test]
    fn range_reads_equal_plaintext_slice(
        len in 1usize..(3 * SEG + 100),
        seed: u64,
        a in 0u64..(3 * SEG as u64 + 200),
        b in 0u64..(3 * SEG as u64 + 200),
        kind in 0u8..3,
    ) {
        let k = key(4, 4);
        let h = hash(b"r");
        let pt = bytes(len, seed);
        let ct = seal(&k, &kv(&h), pt.clone()).unwrap();
        let header = Header::parse(&ct).unwrap();
        let spec = match kind {
            0 => ByteRangeSpec::Inclusive { start: a.min(b), end: a.max(b) },
            1 => ByteRangeSpec::From { start: a },
            _ => ByteRangeSpec::Suffix { length: a },
        };
        match (spec.resolve(len as u64), header.map_range(spec)) {
            (None, None) => {}
            (Some(want), Some(r)) => {
                prop_assert_eq!(r.plaintext_range(), want);
                prop_assert_eq!(r.total_size(), len as u64);
                let fetched = ct[r.ciphertext_start() as usize..=r.ciphertext_end() as usize].to_vec();
                let dec = DecryptReader::range(&k, &kv(&h), &header, r, Chunked::new(fetched, vec![5000])).unwrap();
                let got = read_all(dec, &[3000]).unwrap();
                prop_assert_eq!(&got[..], &pt[want.start() as usize..=want.end() as usize]);
            }
            (want, got) => prop_assert!(false, "resolve {want:?} vs map {got:?}"),
        }
    }

    #[test]
    fn any_single_byte_flip_is_rejected(len in 0usize..(2 * SEG + 50), seed: u64, at: usize, x in 1u8..=255) {
        let k = key(5, 5);
        let h = hash(b"t");
        let mut ct = seal(&k, &kv(&h), bytes(len, seed)).unwrap();
        let at = at % ct.len();
        ct[at] ^= x;
        prop_assert!(open(&k, &kv(&h), ct.clone()).is_err());
        prop_assert!(stream_open(&k, &kv(&h), &ct).is_err());
    }
}

#[test]
fn salt_is_fresh_per_seal() {
    let k = key(1, 1);
    let h = hash(b"same");
    let a = seal(&k, &kv(&h), b"same plaintext".to_vec()).unwrap();
    let b = seal(&k, &kv(&h), b"same plaintext".to_vec()).unwrap();
    assert_ne!(a[20..52], b[20..52]);
    assert_ne!(a[HEADER_LEN..], b[HEADER_LEN..]);
}

// ---------- truncation, reordering, swapping ----------

#[test]
fn truncation_and_trailing_bytes_are_rejected() {
    let k = key(1, 7);
    let h = hash(b"trunc");
    let p = 3 * SEG; // exactly three full segments
    let ct = seal(&k, &kv(&h), bytes(p, 1)).unwrap();
    let cuts = [
        segment(p, 2).start, // drop the last segment
        segment(p, 1).start, // drop the last two
        HEADER_LEN,          // header only
        ct.len() - 1,        // drop one tag byte
        segment(p, 1).start + 100,
    ];
    for cut in cuts {
        let short = ct[..cut].to_vec();
        assert!(
            matches!(
                open(&k, &kv(&h), short.clone()),
                Err(EnvelopeError::Integrity)
            ),
            "cut {cut}"
        );
        assert!(
            is_integrity(stream_open(&k, &kv(&h), &short)),
            "stream cut {cut}"
        );
    }
    let mut long = ct.clone();
    long.push(0);
    assert!(matches!(
        open(&k, &kv(&h), long.clone()),
        Err(EnvelopeError::Integrity)
    ));
    assert!(is_integrity(stream_open(&k, &kv(&h), &long)));

    // A range read whose fetched span is cut short fails too.
    let header = Header::parse(&ct).unwrap();
    let r = header
        .map_range(ByteRangeSpec::From {
            start: SEG as u64 + 5,
        })
        .unwrap();
    let fetched = ct[r.ciphertext_start() as usize..r.ciphertext_end() as usize].to_vec();
    let dec =
        DecryptReader::range(&k, &kv(&h), &header, r, Chunked::new(fetched, vec![9000])).unwrap();
    assert!(is_integrity(read_all(dec, &[4096])));
}

#[test]
fn reordered_duplicated_and_foreign_segments_are_rejected() {
    let k = key(1, 8);
    let h = hash(b"order");
    let p = 3 * SEG;
    let ct = seal(&k, &kv(&h), bytes(p, 2)).unwrap();
    let (s0, s1, s2) = (segment(p, 0), segment(p, 1), segment(p, 2));

    let mut swapped = ct.clone();
    swapped[s0.clone()].copy_from_slice(&ct[s1.clone()]);
    swapped[s1.clone()].copy_from_slice(&ct[s0.clone()]);
    assert!(matches!(
        open(&k, &kv(&h), swapped.clone()),
        Err(EnvelopeError::Integrity)
    ));
    assert!(is_integrity(stream_open(&k, &kv(&h), &swapped)));

    let mut dup = ct.clone();
    dup[s1.clone()].copy_from_slice(&ct[s0.clone()]);
    assert!(matches!(
        open(&k, &kv(&h), dup),
        Err(EnvelopeError::Integrity)
    ));

    // Last segment moved into a middle slot: its last-flag nonce no longer fits.
    let mut last_mid = ct.clone();
    last_mid[s1.clone()].copy_from_slice(&ct[s2.clone()]);
    assert!(matches!(
        open(&k, &kv(&h), last_mid),
        Err(EnvelopeError::Integrity)
    ));

    // Same key, same identity, same plaintext, another blob: segments don't transplant.
    let other = seal(&k, &kv(&h), bytes(p, 2)).unwrap();
    let mut spliced = ct.clone();
    spliced[s1.clone()].copy_from_slice(&other[s1.clone()]);
    assert!(matches!(
        open(&k, &kv(&h), spliced),
        Err(EnvelopeError::Integrity)
    ));
    let mut header_swap = other.clone();
    header_swap[..HEADER_LEN].copy_from_slice(&ct[..HEADER_LEN]);
    assert!(matches!(
        open(&k, &kv(&h), header_swap),
        Err(EnvelopeError::Integrity)
    ));
}

// ---------- identity and key binding ----------

#[test]
fn ciphertext_is_bound_to_its_identity() {
    let k = key(1, 6);
    let h = hash(b"content");
    let h2 = hash(b"other content");
    let ckpt = |space, name, hash, size| BlobIdentity::SqlCheckpoint {
        service: "sqlite",
        space,
        name,
        checkpoint_content_hash: hash,
        checkpoint_size_bytes: size,
    };
    let wal = |rev, base, delta| BlobIdentity::SqlWal {
        service: "sqlite",
        space: SPACE,
        name: "db",
        revision: rev,
        checkpoint_content_hash: base,
        delta_content_hash: delta,
    };
    let cases: Vec<(BlobIdentity<'_>, Vec<BlobIdentity<'_>>)> = vec![
        (
            kv(&h),
            vec![
                BlobIdentity::KvBlock {
                    space:
                        "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:default",
                    content_hash: &h,
                },
                kv(&h2),
                ckpt(SPACE, "", "", 0),
            ],
        ),
        (
            ckpt(SPACE, "db", "c1", 10),
            vec![
                ckpt(SPACE, "db2", "c1", 10),
                ckpt(SPACE, "db", "c2", 10),
                ckpt(SPACE, "db", "c1", 11),
                ckpt("tinycloud:other:x:default", "db", "c1", 10),
                BlobIdentity::SqlCheckpoint {
                    service: "duckdb",
                    space: SPACE,
                    name: "db",
                    checkpoint_content_hash: "c1",
                    checkpoint_size_bytes: 10,
                },
                wal(10, "c1", ""),
            ],
        ),
        (
            wal(5, "c1", "d1"),
            vec![wal(6, "c1", "d1"), wal(5, "c2", "d1"), wal(5, "c1", "d2")],
        ),
        // Length prefixes: moving bytes between adjacent fields changes the identity.
        (ckpt(SPACE, "ab", "c", 1), vec![ckpt(SPACE, "a", "bc", 1)]),
    ];
    for (good, bad) in cases {
        let ct = seal(&k, &good, bytes(SEG + 10, 3)).unwrap();
        assert!(open(&k, &good, ct.clone()).is_ok());
        for b in bad {
            assert!(
                matches!(open(&k, &b, ct.clone()), Err(EnvelopeError::Integrity)),
                "{good:?} opened as {b:?}"
            );
            assert!(is_integrity(stream_open(&k, &b, &ct)));
        }
    }
}

#[test]
fn wrong_key_is_rejected() {
    let h = hash(b"k");
    let ct = seal(&key(3, 1), &kv(&h), b"secret".to_vec()).unwrap();
    assert!(matches!(
        open(&key(3, 2), &kv(&h), ct.clone()),
        Err(EnvelopeError::Integrity)
    ));
    assert!(matches!(
        open(&key(4, 1), &kv(&h), ct.clone()),
        Err(EnvelopeError::KeyMismatch)
    ));
    let header = Header::parse(&ct).unwrap();
    assert_eq!(header.dek_id(), DekId::new(3));
    assert!(matches!(
        DecryptReader::new(&key(4, 1), &kv(&h), &header, &ct[HEADER_LEN..]),
        Err(EnvelopeError::KeyMismatch)
    ));
}

// ---------- header and legacy handling ----------

#[test]
fn malformed_headers_are_refused() {
    let k = key(1, 1);
    let h = hash(b"h");
    let ct = seal(&k, &kv(&h), b"abc".to_vec()).unwrap();
    for (at, val, what) in [
        (0, b'X', "magic"),
        (4, 2, "version"),
        (5, 2, "algorithm"),
        (6, 1, "flags"),
        (7, 1, "flags"),
        (52, 15, "segment size"),
        (63, 1, "padding"),
    ] {
        let mut bad = ct.clone();
        bad[at] = val;
        match Header::parse(&bad) {
            Err(EnvelopeError::Header(w)) => assert_eq!(w, what, "byte {at}"),
            other => panic!("byte {at}: {other:?}"),
        }
        assert!(open(&k, &kv(&h), bad).is_err());
    }
    assert!(matches!(
        Header::parse(&ct[..63]),
        Err(EnvelopeError::Header("short header"))
    ));
}

#[test]
fn legacy_plaintext_is_never_returned_as_plaintext() {
    let k = key(1, 1);
    let h = hash(b"legacy");
    let mut sqlite = b"SQLite format 3\0".to_vec();
    sqlite.resize(4096, 0);
    for legacy in [
        sqlite,
        b"just some user bytes".to_vec(),
        vec![0x01; 100],
        Vec::new(),
    ] {
        assert!(matches!(
            open(&k, &kv(&h), legacy),
            Err(EnvelopeError::Header(_))
        ));
    }
}

#[test]
fn payload_encoding_column_is_explicit() {
    assert_eq!(
        PayloadEncoding::from_column(None).unwrap(),
        PayloadEncoding::LegacyPlaintext
    );
    assert_eq!(
        PayloadEncoding::from_column(Some(1)).unwrap(),
        PayloadEncoding::Tce1
    );
    for v in [0, 2, -1, i16::MAX] {
        assert!(PayloadEncoding::from_column(Some(v)).is_err(), "{v}");
    }
    for e in [PayloadEncoding::LegacyPlaintext, PayloadEncoding::Tce1] {
        assert_eq!(PayloadEncoding::from_column(e.to_column()).unwrap(), e);
    }
}

#[test]
fn encrypt_reader_enforces_declared_length() {
    let k = key(1, 1);
    let h = hash(b"len");
    for (declared, actual) in [(10u64, 9usize), (10, 11), (SEG as u64, SEG + 1), (0, 1)] {
        let r = EncryptReader::new(
            &k,
            &kv(&h),
            declared,
            Chunked::new(vec![7; actual], vec![3]),
        )
        .unwrap();
        let err = read_all(r, &[100]).unwrap_err();
        assert!(
            matches!(
                err.get_ref()
                    .and_then(|e| e.downcast_ref::<EnvelopeError>()),
                Some(EnvelopeError::LengthMismatch)
            ),
            "{declared}/{actual}: {err}"
        );
    }
}

/// Over-long input must fail before the final segment is released, so a
/// consumer that stops reading at `ciphertext_len` never holds a complete,
/// valid object of a prefix.
#[test]
fn over_long_input_never_yields_the_final_segment() {
    let k = key(1, 1);
    let h = hash(b"long");
    for declared in [0usize, 10, SEG - 1, SEG, SEG + 10, 2 * SEG] {
        let n = declared.div_ceil(SEG).max(1);
        let final_start = segment_offset(n as u64 - 1) as usize;
        for sizes in [vec![1], vec![3], vec![SEG + 100]] {
            let mut r = EncryptReader::new(
                &k,
                &kv(&h),
                declared as u64,
                Chunked::new(vec![7; declared + 1], sizes.clone()),
            )
            .unwrap();
            let mut got = Vec::new();
            let err = futures::executor::block_on(async {
                let mut buf = [0u8; 4096];
                loop {
                    match r.read(&mut buf).await {
                        Ok(0) => return None,
                        Ok(m) => got.extend_from_slice(&buf[..m]),
                        Err(e) => return Some(e),
                    }
                }
            })
            .unwrap_or_else(|| panic!("{declared}/{sizes:?}: no error"));
            assert!(
                matches!(
                    err.get_ref()
                        .and_then(|e| e.downcast_ref::<EnvelopeError>()),
                    Some(EnvelopeError::LengthMismatch)
                ),
                "{declared}: {err}"
            );
            assert!(
                got.len() <= final_start,
                "{declared}/{sizes:?}: {} bytes released, final segment starts at {final_start}",
                got.len()
            );
            assert!(open(&k, &kv(&h), got).is_err());
        }
    }
}

#[test]
fn range_from_another_header_is_refused() {
    let k = key(1, 1);
    let h = hash(b"rr");
    let a = Header::parse(&seal(&k, &kv(&h), vec![1; 100]).unwrap()).unwrap();
    let b = Header::parse(&seal(&k, &kv(&h), vec![1; 200]).unwrap()).unwrap();
    let r = b.map_range(ByteRangeSpec::From { start: 150 }).unwrap();
    assert!(matches!(
        DecryptReader::range(&k, &kv(&h), &a, r, &[][..]),
        Err(EnvelopeError::Header(_))
    ));
}

#[test]
fn sealed_names_hide_space_and_hash() {
    let nk = ObjectNameKey::new([3; 32]);
    let h = hash(b"file");
    let name = sealed_object_name(&nk, SPACE, &h);
    let parts: Vec<_> = name.split('/').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0], "v1");
    assert_eq!(parts[1], space_tag(&nk, SPACE));
    assert_eq!((parts[1].len(), parts[2].len()), (22, 43));
    assert!(!name
        .to_lowercase()
        .contains("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"));
    let legacy_digest =
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE, h.as_ref());
    assert!(!name.contains(legacy_digest.trim_end_matches('=')));
    assert_eq!(name, sealed_object_name(&nk, SPACE, &h));
    assert_ne!(name, sealed_object_name(&nk, SPACE, &hash(b"file2")));
    assert_ne!(
        name,
        sealed_object_name(&ObjectNameKey::new([4; 32]), SPACE, &h)
    );
    let other = "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:default";
    assert_ne!(space_tag(&nk, SPACE), space_tag(&nk, other));
    assert!(
        sealed_object_name(&nk, other, &h).starts_with(&format!("v1/{}/", space_tag(&nk, other)))
    );
}
