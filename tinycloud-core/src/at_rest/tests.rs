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
    negative: Vec<serde_json::Value>,
    lengths: Lengths,
    ranges: Vec<RangeVector>,
}

#[derive(serde::Deserialize)]
struct Lengths {
    plaintext_to_ciphertext: Vec<LengthPair>,
    ciphertext_to_plaintext: Vec<LengthPair>,
}

#[derive(serde::Deserialize)]
struct LengthPair {
    plaintext_len: Option<u64>,
    ciphertext_len: Option<u64>,
}

#[derive(serde::Deserialize)]
struct RangeVector {
    total: u64,
    spec: serde_json::Value,
    mapped: Option<MappedRange>,
}

#[derive(serde::Deserialize, Debug, PartialEq)]
struct MappedRange {
    plaintext_start: u64,
    plaintext_end: u64,
    ciphertext_start: u64,
    ciphertext_end: u64,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("testdata/vectors.json")).unwrap()
}

fn vector_plaintext(t: &Vector) -> Vec<u8> {
    match t.plaintext.get("hex") {
        Some(h) => hex::decode(h.as_str().unwrap()).unwrap(),
        None => (0..t.plaintext["pattern_len"].as_u64().unwrap())
            .map(|i| (i % 251) as u8)
            .collect(),
    }
}

fn with_identity<T>(i: &serde_json::Value, f: impl FnOnce(&BlobIdentity<'_>) -> T) -> T {
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
    f(&id)
}

fn range_spec(v: &serde_json::Value) -> ByteRangeSpec {
    let n = |k: &str| v[k].as_u64().unwrap();
    match s(v, "kind") {
        "inclusive" => ByteRangeSpec::Inclusive {
            start: n("start"),
            end: n("end"),
        },
        "from" => ByteRangeSpec::From { start: n("start") },
        "suffix" => ByteRangeSpec::Suffix {
            length: n("length"),
        },
        k => panic!("unknown range kind {k}"),
    }
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
    let v = vectors();
    assert_eq!(v.vectors.len(), 8);
    for t in &v.vectors {
        let k = DataKey::new(DekId::new(t.dek_id), arr32(&t.dek));
        let pt = vector_plaintext(t);
        with_identity(&t.identity, |id| kat_one(t, &k, id, &pt));
    }

    for n in &v.object_names {
        let nk = ObjectNameKey::new(arr32(&n.nk));
        let h = Hash::try_from(hex::decode(&n.content_hash).unwrap()).unwrap();
        assert_eq!(space_tag(&nk, &n.space), n.space_tag);
        assert_eq!(sealed_object_name(&nk, &n.space, &h), n.object_name);
    }
}

fn kat_one(t: &Vector, k: &DataKey, id: &BlobIdentity<'_>, pt: &[u8]) {
    use sha2::{Digest, Sha256};
    let header = Header::build(k.id(), pt.len() as u64, &arr32(&t.salt));

    let ct = seal_with_header(k, id, &header, pt.to_vec());
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
        EncryptReader::with_header(k, id, &header, Chunked::new(pt.to_vec(), vec![777])),
        &[1000],
    )
    .unwrap();
    assert_eq!(streamed, ct, "{} streaming", t.name);
    assert_eq!(open(k, id, ct.clone()).unwrap(), pt, "{}", t.name);
    assert_eq!(stream_open(k, id, &ct).unwrap(), pt, "{}", t.name);
}

fn error_kind(e: &EnvelopeError) -> &'static str {
    match e {
        EnvelopeError::Header(_) => "header",
        EnvelopeError::Unsupported { .. } => "unsupported",
        EnvelopeError::Integrity => "integrity",
        other => panic!("unexpected {other:?}"),
    }
}

/// Mutations the Python reference opener rejects must be rejected the same
/// way here, whole-buffer and streaming.
#[test]
fn negative_vectors_are_refused_like_the_reference() {
    let v = vectors();
    assert!(v.negative.len() >= 15);
    for n in &v.negative {
        let base = v.vectors.iter().find(|t| t.name == s(n, "base")).unwrap();
        let k = DataKey::new(DekId::new(base.dek_id), arr32(&base.dek));
        let header = Header::build(
            k.id(),
            vector_plaintext(base).len() as u64,
            &arr32(&base.salt),
        );
        let mut ct = with_identity(&base.identity, |id| {
            seal_with_header(&k, id, &header, vector_plaintext(base))
        });
        let at = || n["at"].as_u64().unwrap() as usize;
        match s(n, "op") {
            "truncate" => ct.truncate(n["len"].as_u64().unwrap() as usize),
            "append" => ct.extend(hex::decode(s(n, "hex")).unwrap()),
            "xor" => ct[at()] ^= n["mask"].as_u64().unwrap() as u8,
            "set" => {
                let b = hex::decode(s(n, "hex")).unwrap();
                ct[at()..at() + b.len()].copy_from_slice(&b);
            }
            "swap_segments" => {
                let p = vector_plaintext(base).len();
                let (a, b) = (
                    n["a"].as_u64().unwrap() as usize,
                    n["b"].as_u64().unwrap() as usize,
                );
                let (ra, rb) = (segment(p, a), segment(p, b));
                let (sa, sb) = (ct[ra.clone()].to_vec(), ct[rb.clone()].to_vec());
                ct[ra].copy_from_slice(&sb);
                ct[rb].copy_from_slice(&sa);
            }
            op => panic!("unknown op {op}"),
        }
        let expect = s(n, "expect");
        with_identity(&base.identity, |id| {
            let e = open(&k, id, ct.clone()).unwrap_err();
            assert_eq!(error_kind(&e), expect, "{n}: {e:?}");
            let se = stream_open(&k, id, &ct).unwrap_err();
            let inner = se.get_ref().and_then(|e| e.downcast_ref::<EnvelopeError>());
            assert_eq!(inner.map(error_kind), Some(expect), "{n} streaming: {se}");
        });
    }
}

#[test]
fn length_vectors_match_reference() {
    let v = vectors();
    for l in &v.lengths.plaintext_to_ciphertext {
        let p = l.plaintext_len.unwrap();
        match (ciphertext_len(p), l.ciphertext_len) {
            (Ok(c), Some(want)) => assert_eq!(c, want, "p={p}"),
            (Err(EnvelopeError::TooLarge), None) => {}
            (got, want) => panic!("p={p}: {got:?} vs {want:?}"),
        }
    }
    for l in &v.lengths.ciphertext_to_plaintext {
        let c = l.ciphertext_len.unwrap();
        assert_eq!(plaintext_len(c), l.plaintext_len, "c={c}");
    }
}

/// Range mapping against the reference, then a real ranged decrypt of each
/// satisfiable range.
#[test]
fn range_vectors_match_reference() {
    let v = vectors();
    assert!(v.ranges.len() > 300);
    let k = key(1, 2);
    let h = hash(b"range-kat");
    let mut sealed = std::collections::HashMap::new();
    for r in &v.ranges {
        let pt = bytes(r.total as usize, r.total);
        let ct = sealed
            .entry(r.total)
            .or_insert_with(|| seal(&k, &kv(&h), pt.clone()).unwrap())
            .clone();
        let header = Header::parse(&ct).unwrap();
        let spec = range_spec(&r.spec);
        let got = header.map_range(spec).map(|m| MappedRange {
            plaintext_start: m.plaintext_range().start(),
            plaintext_end: m.plaintext_range().end(),
            ciphertext_start: m.ciphertext_start(),
            ciphertext_end: m.ciphertext_end(),
        });
        assert_eq!(got, r.mapped, "total {} spec {}", r.total, r.spec);
        if let Some(m) = header.map_range(spec) {
            assert_eq!(m.total_size(), r.total);
            let fetched = ct[m.ciphertext_start() as usize..=m.ciphertext_end() as usize].to_vec();
            let dec = DecryptReader::range(&k, &kv(&h), &header, m, &fetched[..]).unwrap();
            let out = read_all(dec, &[65536]).unwrap();
            let pr = m.plaintext_range();
            assert_eq!(out.len() as u64, pr.len());
            assert_eq!(&out[..], &pt[pr.start() as usize..=pr.end() as usize]);
        }
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
    for v in [2i16, 3, 9] {
        assert!(
            matches!(
                PayloadEncoding::from_column(Some(v)),
                Err(EnvelopeError::Unsupported { version }) if version as i16 == v
            ),
            "{v}"
        );
    }
    for v in [0, -1, 10, 255, 256, i16::MAX, i16::MIN] {
        assert!(
            matches!(
                PayloadEncoding::from_column(Some(v)),
                Err(EnvelopeError::Header(_))
            ),
            "{v}"
        );
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

// ---------- review round: boundaries, partial output, versions ----------

/// Lengths and range endpoints biased to segment edges (k·SEG−1, k·SEG,
/// k·SEG+1) and to the end of the blob (len−1, len, len+1).
fn len_and_points() -> impl Strategy<Value = (usize, u64, u64)> {
    let edge = |k: u64, d: i64| (k as i64 * SEG as i64 + d).max(1) as u64;
    (1u64..4, -1i64..=1)
        .prop_map(move |(k, d)| edge(k, d) as usize)
        .prop_flat_map(move |len| {
            let point = prop_oneof![
                (0u64..4, -1i64..=1)
                    .prop_map(move |(k, d)| (k as i64 * SEG as i64 + d).max(0) as u64),
                (-1i64..=1).prop_map(move |d| (len as i64 + d) as u64),
                0u64..(len as u64 + 2),
            ];
            (Just(len), point.clone(), point)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn edge_biased_ranges_equal_plaintext_slice((len, a, b) in len_and_points(), kind in 0u8..3, seed: u64) {
        let k = key(4, 5);
        let h = hash(b"edge");
        let pt = bytes(len, seed);
        let ct = seal(&k, &kv(&h), pt.clone()).unwrap();
        let header = Header::parse(&ct).unwrap();
        let spec = match kind {
            0 => ByteRangeSpec::Inclusive { start: a.min(b), end: a.max(b) },
            1 => ByteRangeSpec::From { start: a },
            _ => ByteRangeSpec::Suffix { length: a },
        };
        let want = spec.resolve(len as u64);
        let got = header.map_range(spec);
        prop_assert_eq!(want.is_some(), got.is_some());
        if let (Some(want), Some(r)) = (want, got) {
            prop_assert_eq!(r.plaintext_range(), want);
            prop_assert_eq!(r.ciphertext_start() as usize % (SEG + TAG_LEN), HEADER_LEN % (SEG + TAG_LEN));
            prop_assert_eq!(r.ciphertext_end() as usize + 1 == ct.len(), want.end() as usize / SEG == (len - 1) / SEG);
            let fetched = ct[r.ciphertext_start() as usize..=r.ciphertext_end() as usize].to_vec();
            let dec = DecryptReader::range(&k, &kv(&h), &header, r, Chunked::new(fetched, vec![7000])).unwrap();
            let out = read_all(dec, &[4096]).unwrap();
            prop_assert_eq!(out.len() as u64, want.len());
            prop_assert_eq!(&out[..], &pt[want.start() as usize..=want.end() as usize]);
        }
    }
}

#[test]
fn empty_blob_has_no_satisfiable_range() {
    let k = key(1, 1);
    let h = hash(b"empty");
    let ct = seal(&k, &kv(&h), Vec::new()).unwrap();
    let header = Header::parse(&ct).unwrap();
    assert_eq!(header.plaintext_len(), 0);
    for spec in [
        ByteRangeSpec::Inclusive { start: 0, end: 0 },
        ByteRangeSpec::Inclusive {
            start: 0,
            end: u64::MAX,
        },
        ByteRangeSpec::From { start: 0 },
        ByteRangeSpec::Suffix { length: 0 },
        ByteRangeSpec::Suffix { length: 1 },
        ByteRangeSpec::Suffix { length: u64::MAX },
    ] {
        assert_eq!(header.map_range(spec), None, "{spec:?}");
    }
    assert_eq!(stream_open(&k, &kv(&h), &ct).unwrap(), Vec::<u8>::new());
}

/// Reads until the first error; returns what was yielded and the error.
fn read_until_err<R: AsyncRead + Unpin>(r: &mut R) -> (Vec<u8>, io::Error) {
    futures::executor::block_on(async {
        let mut got = Vec::new();
        let mut buf = [0u8; 3000];
        loop {
            match r.read(&mut buf).await {
                Ok(0) => panic!("stream ended without an error"),
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) => return (got, e),
            }
        }
    })
}

#[test]
fn failing_segment_releases_nothing_and_errors_stick() {
    let k = key(1, 3);
    let h = hash(b"partial");
    let p = 4 * SEG;
    let pt = bytes(p, 9);
    let ct = seal(&k, &kv(&h), pt.clone()).unwrap();
    let header = Header::parse(&ct).unwrap();
    for bad in 0..4 {
        let mut c = ct.clone();
        c[segment(p, bad).start + 17] ^= 0x40;

        let mut whole = DecryptReader::new(
            &k,
            &kv(&h),
            &header,
            Chunked::new(c[HEADER_LEN..].to_vec(), vec![5000]),
        )
        .unwrap();
        let (got, err) = read_until_err(&mut whole);
        assert_eq!(got, pt[..bad * SEG], "segment {bad}");
        assert!(is_integrity(Err(err)));
        let again = futures::executor::block_on(whole.read(&mut [0u8; 10]));
        assert!(again.is_err(), "error must be sticky");

        // A range starting mid-segment 0 and spanning everything.
        let r = header
            .map_range(ByteRangeSpec::From { start: 100 })
            .unwrap();
        let fetched = c[r.ciphertext_start() as usize..].to_vec();
        let mut ranged =
            DecryptReader::range(&k, &kv(&h), &header, r, Chunked::new(fetched, vec![5000]))
                .unwrap();
        let (got, err) = read_until_err(&mut ranged);
        assert_eq!(
            got,
            pt[100.min(bad * SEG)..bad * SEG],
            "range, segment {bad}"
        );
        assert!(is_integrity(Err(err)));
        assert!(futures::executor::block_on(ranged.read(&mut [0u8; 10])).is_err());
    }
}

#[test]
fn range_with_trailing_bytes_is_refused() {
    let k = key(1, 4);
    let h = hash(b"trail");
    let p = 2 * SEG + 10;
    let pt = bytes(p, 4);
    let ct = seal(&k, &kv(&h), pt.clone()).unwrap();
    let header = Header::parse(&ct).unwrap();
    for spec in [
        ByteRangeSpec::Inclusive {
            start: 10,
            end: SEG as u64 + 5,
        },
        ByteRangeSpec::Suffix { length: 3 },
    ] {
        let r = header.map_range(spec).unwrap();
        let mut fetched = ct[r.ciphertext_start() as usize..=r.ciphertext_end() as usize].to_vec();
        fetched.push(0);
        let dec = DecryptReader::range(&k, &kv(&h), &header, r, &fetched[..]).unwrap();
        assert!(is_integrity(read_all(dec, &[4096])), "{spec:?}");
    }
}

#[test]
fn size_limits_at_two_to_the_48() {
    let max = (1u64 << 32) * SEG as u64;
    let c = ciphertext_len(max).unwrap();
    assert_eq!(c, max + HEADER_LEN as u64 + (1u64 << 32) * TAG_LEN as u64);
    assert_eq!(plaintext_len(c), Some(max));
    assert_eq!(plaintext_len(c + 1), None);
    for p in [max + 1, u64::MAX] {
        assert!(
            matches!(ciphertext_len(p), Err(EnvelopeError::TooLarge)),
            "{p}"
        );
    }
    assert_eq!(plaintext_len(u64::MAX), None);

    let k = key(1, 1);
    let ok = Header::build(k.id(), max, &[0; 32]);
    assert_eq!(Header::parse(ok.as_bytes()).unwrap().plaintext_len(), max);
    for p in [max + 1, u64::MAX] {
        let mut b = *ok.as_bytes();
        b[12..20].copy_from_slice(&p.to_be_bytes());
        assert!(
            matches!(Header::parse(&b), Err(EnvelopeError::Header("length"))),
            "{p}"
        );
    }
}

#[test]
fn later_generations_are_unsupported_not_corrupt() {
    let k = key(1, 1);
    let h = hash(b"gen");
    let ct = seal(&k, &kv(&h), b"abc".to_vec()).unwrap();
    assert_eq!(format_version(&ct).unwrap(), 1);
    for g in [2u8, 9] {
        let mut c = ct.clone();
        c[3] = b'0' + g;
        c[4] = g;
        assert_eq!(format_version(&c).unwrap(), g);
        assert!(
            matches!(Header::parse(&c), Err(EnvelopeError::Unsupported { version }) if version == g)
        );
        assert!(
            matches!(open(&k, &kv(&h), c.clone()), Err(EnvelopeError::Unsupported { version }) if version == g)
        );
        // Dispatch needs only the first 5 bytes, even if the rest differs in size.
        assert!(matches!(
            Header::parse(&c[..5]),
            Err(EnvelopeError::Unsupported { .. })
        ));
    }
    for (b3, b4) in [(b'2', 1u8), (b'1', 2), (b'0', 0), (b'A', 17)] {
        let mut c = ct.clone();
        c[3] = b3;
        c[4] = b4;
        assert!(
            matches!(Header::parse(&c), Err(EnvelopeError::Header("version"))),
            "{b3} {b4}"
        );
    }
    assert!(matches!(
        format_version(b"TCE"),
        Err(EnvelopeError::Header("short header"))
    ));
}
