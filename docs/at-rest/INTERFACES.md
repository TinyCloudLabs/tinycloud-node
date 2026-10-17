# Encryption at rest: interfaces (TC-887)

> **Status (TC-887):** on `main` today: the envelope, key types, `DataKeyProvider` and the
> harness. Not on `main` yet: key continuity (`docs/at-rest-escrow.md`, `at_rest::keyring`,
> node wiring) and sealed KV storage (§7). They land with PRs #325–#327 and #329/#333/#336
> (#336: the S3 store seals KV blocks).

Normative interface and format for `tinycloud_core::at_rest` and the node's sealed KV block
storage. Plan: TC-887 (encryption at rest inside the TEE). Key continuity and escrow:
`docs/at-rest-escrow.md`.

Responsibilities:
- **Key continuity** (`at_rest::keyring`, node `at_rest` wiring) owns the root → wrap key →
  at-rest root key → KEK/NK hierarchy, data-key (DEK) creation, wrap/unwrap and caching, the
  key tables, escrow, the encrypt gate, locked mode and the `off`/`encrypt`/`strict` mode
  config. It implements `DataKeyProvider`.
- **The envelope** (`at_rest::{envelope,stream,names}`) owns everything below the DEK: per-blob
  key derivation, the TCE1 format, AAD, segmenting, streaming, Range mapping, object names
  from NK, and the payload-encoding flag. It takes a `DataKey` value and never calls the
  provider.
- **Storage** (KV block stores; SQL artifacts) glues them: `provider.current_key(space)` →
  seal; parse header → `provider.key(space, header.dek_id())` → open.

## 1. Key types

```rust
/// Per-space data-key id. Allocated by the key store, unique per space (not global).
/// Stored in the TCE1 header as u32 BE.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DekId(u32);
impl DekId { pub const fn new(v: u32) -> Self; pub const fn get(self) -> u32; }

/// An unwrapped 32-byte DEK plus its id. Zeroized on drop; Debug prints only the id.
#[derive(Clone)]
pub struct DataKey { /* id: DekId, bytes: Zeroizing<[u8; 32]> */ }
impl DataKey {
    pub fn new(id: DekId, bytes: [u8; 32]) -> Self;
    pub fn id(&self) -> DekId;
    // no public accessor for the bytes
}

/// NK = HKDF(ARK_1, "object-names/v1"), pinned to ARK generation 1 (TC-887 plan §1.1).
/// Zeroized on drop; Debug redacted.
#[derive(Clone)]
pub struct ObjectNameKey { /* Zeroizing<[u8; 32]> */ }
impl ObjectNameKey { pub fn new(bytes: [u8; 32]) -> Self; }
```

Space identifiers everywhere in this API are `&str` in canonical `SpaceId::to_string()`
form (what PG stores; SQL repo already has `&str`; KV callers pass `space.to_string()`).

## 2. `DataKeyProvider`

```rust
#[async_trait::async_trait]
pub trait DataKeyProvider: Send + Sync {
    /// The DEK new writes in `space` must use. If the space has none, create one
    /// (32 random bytes), wrap it under the current KEK, and store it durably
    /// BEFORE returning. Concurrent first calls (incl. across processes) must
    /// converge on one dek_id (e.g. INSERT … ON CONFLICT DO NOTHING, then re-read).
    async fn current_key(&self, space: &str) -> Result<DataKey, DataKeyError>;

    /// The DEK a stored blob names in its header. Never creates. Must work for
    /// every dek_id ever issued for `space` (old DEKs are never deleted except
    /// by deliberate crypto-shred).
    async fn key(&self, space: &str, dek_id: DekId) -> Result<DataKey, DataKeyError>;

    /// Before work that may read `space`'s sealed blobs under the invoke write
    /// lock: put back any of the space's keys the database lost (from an
    /// authenticated mirror). Never creates a key. Locked keys are not an error
    /// here (the read itself answers 503).
    async fn prepare_read(&self, space: &str) -> Result<(), DataKeyError>;

    /// NK for sealed S3 object names. Same value for the life of the deployment.
    fn object_name_key(&self) -> Result<ObjectNameKey, DataKeyError>;
}

/// Work under the invoke write lock and transaction runs inside
/// `write_locked(..)`; there `current_key`/`key` make no key-store writes and
/// answer `NotPrepared` for a key that would need creating or restoring.
pub async fn write_locked<F: Future>(f: F) -> F::Output;
pub fn in_write_lock() -> bool;

#[derive(Debug, thiserror::Error)]
pub enum DataKeyError {
    /// Node booted locked (W cannot unseal ARK). Callers map to HTTP 503.
    #[error("at-rest keys are locked")]
    Locked,
    /// Header names a dek_id this space never had (or it was shredded).
    /// Callers map to an integrity error, never to "not found".
    #[error("unknown data key {dek_id:?} for space")]
    UnknownKey { dek_id: DekId },
    /// PG/S3/unwrap failure (incl. a wrapped DEK failing AEAD). Opaque, no key bytes.
    #[error("data key backend: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// A key needed creating or restoring inside `write_locked`. HTTP 503.
    #[error("the space's data key was not prepared before the write lock")]
    NotPrepared,
}
```

## 3. Envelope API

```rust
pub const HEADER_LEN: usize = 64;
pub const SEGMENT_LEN: usize = 1 << 16;          // plaintext bytes per segment
pub const TAG_LEN: usize = 16;

pub enum BlobIdentity<'a> {                      // what the ciphertext is bound to (§4)
    KvBlock       { space: &'a str, content_hash: &'a Hash },
    SqlCheckpoint { service: &'a str, space: &'a str, name: &'a str,
                    checkpoint_content_hash: &'a str, checkpoint_size_bytes: u64 },
    SqlWal        { service: &'a str, space: &'a str, name: &'a str, revision: i64,
                    checkpoint_content_hash: &'a str, delta_content_hash: &'a str },
}

/// Parsed, validated 64-byte header (unknown version/alg/flags/padding refused).
pub struct Header { /* raw bytes, dek_id, plaintext_len */ }
impl Header {
    pub fn parse(bytes: &[u8]) -> Result<Header, EnvelopeError>;  // reads the first 64 bytes
    pub fn as_bytes(&self) -> &[u8; 64];
    pub fn dek_id(&self) -> DekId;
    pub fn plaintext_len(&self) -> u64;
    pub fn ciphertext_len(&self) -> u64;
    /// Resolves `spec` against the PLAINTEXT length and maps it onto whole segments.
    /// None = unsatisfiable (answer 416 with plaintext_len() as total).
    pub fn map_range(&self, spec: ByteRangeSpec) -> Option<SegmentRange>;
}

pub fn ciphertext_len(plaintext_len: u64) -> Result<u64, EnvelopeError>;
/// Inverse, for the boot size scan: None if `ct_len` is not a valid TCE1 length.
pub fn plaintext_len(ciphertext_len: u64) -> Option<u64>;

/// Whole-buffer seal/open, in place (no extra plaintext-sized allocation).
pub fn seal(key: &DataKey, id: &BlobIdentity<'_>, plaintext: Vec<u8>) -> Result<Vec<u8>, EnvelopeError>;
/// Fails unless header.dek_id == key.id(). Never returns partial plaintext.
pub fn open(key: &DataKey, id: &BlobIdentity<'_>, ciphertext: Vec<u8>) -> Result<Vec<u8>, EnvelopeError>;

/// Streaming (futures::io::AsyncRead, matching storage::Content). `R: Unpin`
/// (wrap with Box::pin). Each holds at most one segment in memory.
pub struct EncryptReader<R>;  // plaintext R of declared length -> header ‖ segments
impl<R: AsyncRead + Unpin> EncryptReader<R> {
    /// Errors (io InvalidData, inner LengthMismatch) if R yields fewer/more bytes than declared.
    pub fn new(key: &DataKey, id: &BlobIdentity<'_>, plaintext_len: u64, inner: R) -> Result<Self, EnvelopeError>;
}
pub struct DecryptReader<R>;  // ciphertext R -> verified plaintext, one segment at a time
impl<R: AsyncRead + Unpin> DecryptReader<R> {
    /// `inner` positioned just after the header.
    pub fn new(key: &DataKey, id: &BlobIdentity<'_>, header: &Header, inner: R) -> Result<Self, EnvelopeError>;
    /// `inner` yields exactly bytes `range.ciphertext_start()..=range.ciphertext_end()`.
    /// Refuses a SegmentRange mapped from a different header.
    pub fn range(key: &DataKey, id: &BlobIdentity<'_>, header: &Header,
                 range: SegmentRange, inner: R) -> Result<Self, EnvelopeError>;
}
/// A mid-stream io::Error (kind InvalidData, inner EnvelopeError::Integrity) means the
/// object is corrupt/truncated; already-yielded bytes were authentic but the response
/// must be aborted, not completed. Errors are sticky (the reader is poisoned).

pub struct SegmentRange { /* opaque */ }
impl SegmentRange {
    pub fn ciphertext_start(&self) -> u64;              // inclusive, absolute offset in object
    pub fn ciphertext_end(&self) -> u64;                // inclusive
    pub fn plaintext_range(&self) -> ResolvedByteRange; // for Content-Range
    pub fn total_size(&self) -> u64;                    // plaintext total
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]   // DataKeyError too
pub enum EnvelopeError {
    Header(&'static str),   // malformed / not TCE: magic, version-byte mismatch, alg, flags, padding, seg size, length; invalid PayloadEncoding (≤0, >9)
    Unsupported { version: u8 }, // well-formed later generation (TCE2+), or PayloadEncoding 2..=9: "upgrade", not corruption
    KeyMismatch,            // header dek_id != key.id()
    Integrity,              // any AEAD failure, truncation, reorder, trailing bytes, foreign identity
    TooLarge,               // > 2^32 segments
    LengthMismatch,         // EncryptReader input length != declared
}
/// First-5-bytes dispatch: "TCE" ‖ ASCII digit g ‖ byte g → Ok(g); else Header.
pub fn format_version(bytes: &[u8]) -> Result<u8, EnvelopeError>;
```

Memory: each reader holds two (64 KiB + 16 B) buffers, allocated once. `seal` reuses the Vec:
pass capacity ≥ `ciphertext_len(len)` to avoid a realloc+copy (SQL artifacts: allocate that up front;
call seal/open in `spawn_blocking` for large payloads).
Key-material residuals (accepted): `aes`/`aes-gcm` `zeroize` wipe the AES key
schedule, but **not** the GHASH key H (polyval 0.6.2's autodetect backend holds it in a
`ManuallyDrop` union with no `Drop`), nor the `hkdf` 0.12 PRK or `hmac` 0.12 state (keyed by
DEK-derived material / NK). Copies may remain in freed memory inside the TEE.

Range flow for S3: GET `bytes=0-63` → `Header::parse` → provider.key → `header.map_range(spec)`
(None → 416 with `header.plaintext_len()` as total) → GET `bytes=ciphertext_start-ciphertext_end`
→ `DecryptReader::range`; `Content-Range` from `plaintext_range()`/`total_size()`.

> **Note for storage callers — header fields are hints until a segment verifies.**
> `Header::parse` checks structure only. The header is authenticated only as AAD of
> each segment, so `plaintext_len()` / `dek_id()` from a header alone can be forged by
> the storage provider (a forged header parses and `map_range` answers `None`). Metadata only, never plaintext, but:
> - HEAD / `Content-Length` / ETag-only paths and 416 totals must not present a
>   header-only size as verified. Every segment's AAD includes the header, so decrypting
>   **any one** segment (e.g. the first, or the one a range needs anyway) authenticates
>   `plaintext_len`/`dek_id`; otherwise record "unverified size" as an accepted risk in
>   the storage design and treat it as a hint (e.g. quota math).
> - A range response's `Content-Range` total becomes trustworthy once the first fetched
>   segment verifies; send headers after that, not before.
> - `UnknownKey` for a header `dek_id` is an integrity failure of the blob, not 404.
> - **`EnvelopeError::Unsupported` is unauthenticated.** It comes from header bytes 3–4 (or
>   the encoding column), which anyone with storage/DB access can flip. KV storage, SQL artifacts and backfill must
>   **fail closed** on it: never treat it as legacy plaintext, never re-seal, rewrite, skip
>   or garbage-collect the blob because of it (backfill and verify passes included); surface
>   it as a hard error (503/500 with "unsupported at-rest format", logged), exactly like an
>   integrity failure except for the operator message.
> - `EncryptReader` now seals the final segment only after the source reports EOF, so a
>   consumer that stops at `ciphertext_len` cannot store a valid prefix of over-long input;
>   still pass `content_length = ciphertext_len(plaintext_len)` and treat any read error
>   as a failed PUT.

## 4. Format (normative; KAT vectors in `at_rest/testdata/vectors.json`, generated by the independent Python reference `at_rest/testdata/gen_vectors.py`)

Header, 64 bytes, all integers big-endian:
```
0  "TCE1"        4
4  version = 1   1
5  alg = 1       1   (AES-256-GCM, HKDF-SHA256, 64 KiB segments)
6  flags = 0     1   (must be 0)
7  reserved = 0  1
8  dek_id        4   u32
12 plaintext_len 8   u64
20 salt          32  random per blob
52 seg_log2 = 16 1
53 zero pad      11  (must be 0)
```
Context (identity) bytes, every variable field `u32 BE len ‖ bytes`:
```
ctx = lp("tinycloud/at-rest/v1") ‖ lp(purpose) ‖ lp(field_1) ‖ … ‖ lp(field_n)
purpose ∈ {"kv-block","sql-checkpoint","sql-wal"}
kv-block:       space, content_hash (multihash bytes)
sql-checkpoint: service, space, name, checkpoint_content_hash, u64 BE checkpoint_size_bytes
sql-wal:        service, space, name, i64 BE revision, checkpoint_content_hash, delta_content_hash
```
Keys and nonces:
```
K_obj  = HKDF-SHA256(ikm = DEK, salt = header.salt, info = SHA-256(ctx), L = 32)
nonce_i = u32 BE i ‖ u8 last(i) ‖ 7 × 0x00          last(i) = 1 iff i == n-1
AAD_i   = ctx ‖ header(64)
n       = max(1, ceil(plaintext_len / 65536))       empty plaintext = one empty segment
segment_i = AES-256-GCM(K_obj, nonce_i, AAD_i, pt[i·64Ki .. min((i+1)·64Ki, len)]) = ct ‖ tag16
ciphertext_len = 64 + plaintext_len + 16·n
```

**Versioning and the TCE2 rule (normative).**
- Bytes 0..5 identify the generation: `"TCE" ‖ ASCII digit g ‖ byte g` (g = 1..9). Both the
  magic digit (byte 3) and the version byte (byte 4) change together; a mismatch is a
  malformed header. TCE1 = `"TCE1" ‖ 0x01`. A TCE2 = `"TCE2" ‖ 0x02` and may change anything
  after byte 5 (header length, layout, algorithms).
- Readers call `format_version` on the first 5 bytes **before** generation-specific parsing
  and dispatch on g. A generation the build doesn't know → `EnvelopeError::Unsupported{g}`
  (operator message: "upgrade the node"), never `Header`/`Integrity`. Not-TCE bytes → `Header`.
- SQL: `payload_encoding`/`delta_encoding` value g (1..=9, the same range the header can
  express) means TCE generation g; NULL = legacy plaintext. A value the build doesn't read →
  `Unsupported{g}`; 0, negative or >9 → `Header` (invalid).
- KV names stay `v1/…`: the name prefix versions the **naming** scheme (NK/HMAC layout), not the
  blob format; a TCE2 blob can live under a `v1/` name, and readers dispatch on the bytes'
  first 5 bytes once the name says "sealed".
- **Writers stay on TCE1 until every binary in the rollback window can read TCE2.** That is a
  config/mode gate set by the operator after a release that reads TCE2 has been deployed
  everywhere and rollback below it is ruled out — not something the column or name decides.

## 5. Legacy vs sealed: explicit, never sniffed

```rust
/// SQL: `database_artifact.payload_encoding` / `delta_encoding` (SMALLINT, NULL = legacy).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadEncoding { LegacyPlaintext, Tce1 }
impl PayloadEncoding {
    pub fn from_column(v: Option<i16>) -> Result<Self, EnvelopeError>;  // None→Legacy, 1→Tce1, 2..=9→Unsupported{g}, else Header
    pub fn to_column(self) -> Option<i16>;
}

/// KV: by S3 name namespace. Legacy names stay `{space}/{b64url(digest)}`.
pub fn space_tag(nk: &ObjectNameKey, space: &str) -> String;       // b64url(HMAC(NK, lp("space")‖lp(space))[..16])
pub fn sealed_object_name(nk: &ObjectNameKey, space: &str, hash: &Hash) -> String;
                                                                    // "v1/{space_tag}/{b64url(HMAC(NK, lp("obj")‖lp(space)‖lp(hash)))}"
```
`open` on bytes that lack the `TCE1` header returns `EnvelopeError::Header`; it never falls
back to plaintext. Whether a blob is legacy is decided by the caller from the name or the
column, before any bytes are read.

## 6. Test helper
`at_rest::FixedKeyProvider` — in-memory `DataKeyProvider` with fixed DEKs per
(space, dek_id) and a `locked()` constructor. No persistence. **Compiled only under
`cfg(test)` in tinycloud-core or with the `test-util` feature**: downstream crates
add `tinycloud-core = { …, features = ["test-util"] }` to `[dev-dependencies]` only. Debug is
redacted.

## 7. KV block storage decisions
- **Decided deviation from TC-887 plan §2 (dedup):** in `encrypt`/`strict`, `contains` checks only the
  sealed name the write would use. An existing legacy plaintext copy does **not** suppress the
  sealed write, so a new put never leaves plaintext as the only copy; the backfill handles only blobs
  that existed before.
- **Accepted residual (header trust):** `Content-Length`/`Content-Range`/416 totals come from the
  unverified header. A forged header can only produce a wrong total or a body that aborts with
  no unauthenticated bytes (test `storage::sealed::tests::forged_header_length_aborts_without_extra_bytes`),
  never wrong bytes.
- **Quota:** plaintext bytes. Sealed objects are scanned by `space_tag` and joined to a space when
  the object-name key is unlocked (lazily, per lookup), so the first quota check after an unlock
  counts legacy + sealed. While locked, a space reports legacy bytes only (writes are 503 then).
  A sealed object with an invalid TCE1 length counts 0 bytes; the warning is rate-limited and
  carries only the length.
- **Errors:** at-rest causes map explicitly to 503 (keys unavailable, key store unavailable, key
  not prepared) or 500 (integrity, unsupported, legacy refused in strict, inconsistent key store)
  on `/invoke` and the KV GET routes. Bodies carry reason codes only; backend detail goes to the
  server log. Integrity and unsupported failures are logged (typed, rate-limited, no names),
  including ones that abort a response mid-stream. The general "store error → 401" catch-all is
  tracked separately (TC-1347).
- **Prepare before the write lock:** while keys are set up, a writing invocation is authorized and
  its spaces' hosting checked *before* any key work, so a refused request creates no data key or
  mirror object. Then every space it touches is prepared: a data key the database lost is restored
  from its authenticated mirror (never created), and written spaces get their current key. Inside
  the invoke write lock and transaction the provider only looks keys up (`at_rest::write_locked`);
  a key that would need creating or restoring there is `NotPrepared` (503), never a key-store
  write, which on SQLite would wait on the lock the request holds.
- **Accepted residual (linkability during the transition):** in `encrypt`, a read of a
  legacy-only block asks for the sealed name first, then the legacy name (`strict` probes the legacy
  name to answer "legacy refused"). A storage provider's access logs can therefore link a
  `space_tag` to its space id (and an object tag to its content hash) for every space read before
  the backfill, for the life of the object-name key.
- **Downgrade window until `strict`:** legacy objects are served without a hash check. In `off` or
  `encrypt`, someone who can write the bucket and delete sealed objects can serve any bytes under the
  legacy names they know. `strict` (after the backfill) closes this.
- **`remove`:** deletes the sealed copy when keys can name it, else the legacy copy. When both
  exist, the legacy copy survives, and while keys are locked only the legacy copy is removed. KV
  delete is logical, so nothing calls it in production today; S5/GC must delete both names.
- **Reserved names:** The key-continuity key mirror lives under `_tc/` in the block bucket (`datadir/at-rest` on
  FS). The block boot scan skips it.
