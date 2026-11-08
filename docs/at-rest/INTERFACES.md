# Encryption at rest: interfaces (TC-887)

> **Status (TC-887):** the envelope, key types, `DataKeyProvider`, the keyring
> (`at_rest::keyring`), the node wiring (`docs/at-rest-escrow.md`), the storage view
> (`at_rest::{AtRestMode, AtRestView, AtRestSource}`), sealed KV storage (§7) and sealed SQL
> artifacts (§8) are in. Both declare their seal path, so `encrypt` and `strict` can be configured.

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
    /// lock: put back any of the space's keys the database lost (for example
    /// from an authenticated mirror). Never creates a key.
    async fn prepare_read(&self, space: &str) -> Result<(), DataKeyError>;

    /// NK for sealed S3 object names. Same value for the life of the deployment.
    fn object_name_key(&self) -> Result<ObjectNameKey, DataKeyError>;
}

/// Runs `f` as work under the invoke write lock: providers make no key-store
/// writes there; a key that would need creating or restoring is `NotPrepared`.
pub async fn write_locked<F: Future>(f: F) -> F::Output;

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
    /// A key needed creating or restoring inside `write_locked`. Callers map to 503.
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
    SqlManifest   { service: &'a str, space: &'a str, name: &'a str, revision: i64,
                    content_hash: &'a str, size_bytes: i64,
                    checkpoint: SqlManifestPart<'a>, delta: Option<SqlManifestPart<'a>> },
}
pub struct SqlManifestPart<'a> { pub content_hash: &'a str, pub size_bytes: i64,
                                 pub encoding: Option<i16> }   // §8

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
purpose ∈ {"kv-block","sql-checkpoint","sql-wal","sql-manifest"}
kv-block:       space, content_hash (multihash bytes)
sql-checkpoint: service, space, name, checkpoint_content_hash, u64 BE checkpoint_size_bytes
sql-wal:        service, space, name, i64 BE revision, checkpoint_content_hash, delta_content_hash
sql-manifest:   service, space, name, i64 BE revision, content_hash, i64 BE size_bytes,
                part(checkpoint), then [0x00] (no delta) or [0x01], part(delta)
part(p):        p.content_hash, i64 BE p.size_bytes, p.encoding (empty = NULL, else i16 BE)
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

**Generation suffix.** A KV blob lifetime is `(space, content hash, generation)` (TC-735): the
legacy name of generation `N > 0` is `{space}/{b64url(digest)}@N`, generation 0 has no suffix.
The sealed name follows the same rule: `sealed_object_name(nk, space, hash)` plus `@N` for
`N > 0`. The suffix is appended outside the HMAC, so the HMAC inputs (and the KAT vectors) are
unchanged, and the AEAD identity (`BlobIdentity::KvBlock { space, content_hash }`) does not
include the generation. On disk the sealed name is the path `v1/{space_tag}/{object_tag}[@N]`
under the block directory.

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
  never wrong bytes. On S3 a range read's segment GET is pinned to the header GET's ETag
  (`If-Match`) and its `Content-Range` must equal the computed ciphertext span: if the object is
  replaced or removed in between, the read starts over once, then answers 503. It never falls back
  to the legacy name once a sealed header was read.
- **S3 deletion charges:** a lost DELETE response is settled per copy (legacy and sealed are
  tracked apart). The boot listing can't name sealed objects (keys arrive after storage opens), so
  a sealed object whose DELETE lands after a restart's listing stays counted until the next
  restart (a conservative over-count, never an under-count).
- **Quota:** plaintext bytes. Sealed objects are scanned by `space_tag` and joined to a space when
  the object-name key is unlocked (lazily, per lookup), so the first quota check after an unlock
  counts legacy + sealed. While locked, a space reports legacy bytes only (writes are 503 then).
  A sealed object with an invalid TCE1 length counts 0 bytes; the warning is rate-limited and
  carries only the length. The S3 boot scan lists `v1/` separately from the KV prefix; the FS
  scan reads `{blocks}/v1/` (not a DID directory). A `.tc-stage-` file under `v1/` is charged its
  stored bytes, like a stage in a space directory. Seeding a hosted space's entry (TC-1578) never
  resets or hides the bytes counted under its tag.
- **Errors:** at-rest causes map explicitly to 503 (keys unavailable, key store unavailable, key
  not prepared) or 500 (integrity, unsupported, legacy refused in strict, inconsistent key store)
  on `/invoke` and the KV GET routes (signed and public). Bodies carry reason codes only; backend
  detail goes to the server log. Integrity and unsupported failures are logged (typed,
  rate-limited, named by the sealed name only), including ones that abort a response
  mid-stream. The general "store error → 401" catch-all is tracked separately (TC-1347).
- **Prepare before the write lock:** a writing invocation's spaces are prepared after the
  preupload transaction (TC-735) authorized it and checked its spaces are hosted, and before any
  upload, sequence or writer lock, or transaction: written spaces get their current data key
  (created if new), spaces a `kv/get` reads in the transaction get any data key the database lost
  restored from its authenticated mirror (never created). A request refused by its authorization
  or hosting checks therefore creates no data key or mirror object; no separate pre-authorization
  is needed (the preupload transaction already authorizes before any key work). Work under the
  writer lock (a `kv/get` in a writing invocation, the upload of a protected legacy meeting path)
  runs in `at_rest::write_locked`, where the provider only looks keys up and a key that would
  need creating or restoring is `NotPrepared` (503), never a key-store write that would wait on
  the lock the request holds. Read-only invocations and the KV GET routes hold no writer lock, so
  a key the database lost is restored on first use there.
- **Accepted residual (late refusals prepare keys):** a refusal that comes after the spaces were
  prepared, in the write's own transaction (a failed `If-Match`/`If-None-Match` precondition, 412,
  or a replayed invocation, 409), can leave a new data key and its mirror object for a space it
  wrote nothing to. It is the key that space's first write would create; nothing is sealed under it.
- **Accepted residual (generation not in the AEAD identity):** a block's AAD binds its space and
  content hash but not its `@N` generation (§5), so a sealed object of one generation opens in
  place of another generation of the same block. Every generation holds the same plaintext (the
  content hash), so only same-content replay is possible.
- **Accepted residual (linkability during the transition):** in `encrypt`, a read of a
  legacy-only block asks for the sealed name first, then the legacy name (`strict` probes the legacy
  name to answer "legacy refused"). A storage provider's access logs can therefore link a
  `space_tag` to its space id (and an object tag to its content hash) for every space read before
  the backfill, for the life of the object-name key.
- **Downgrade window until `strict`:** legacy objects are served without a hash check. In `off` or
  `encrypt`, someone who can write the bucket and delete sealed objects can serve any bytes under the
  legacy names they know. `strict` (after the backfill) closes this.
- **Removal (orphan collection, TC-735):** `remove` deletes both copies of the generation, the
  sealed name and the legacy name, and `cleanup_stages` reclaims incomplete stages beside both.
  While keys are set up but locked the sealed name cannot be computed, so both refuse (503) and the
  collector retries later; a sealed object is never left behind unnamed while its candidate is
  retired. On disk a crashed sealed write leaves `v1/{space_tag}/.tc-stage-{object}-*`, charged its
  stored bytes at boot like a stage in a space directory.
- **Reserved names:** The key-continuity key mirror lives under `_tc/` in the block bucket (`datadir/at-rest` on
  FS). The block boot scan skips it.

## 8. SQL artifacts
External authoritative payloads are sealed: the durable copy of each SQL and DuckDB database is a
`database_artifact` row, `payload` (the checkpoint) and `delta_payload` (the WAL delta).
`SeaOrmDatabaseArtifactRepository` seals and opens them; it reads a fresh `AtRestView` per
operation (`with_at_rest`), and the node's repository declares `SealPath::SqlArtifacts`.
- **Local working files are not sealed (known limitation, a later phase).** Local working files
  (SQL and DuckDB working and cache files, upload staging, exports) rely on the CVM's encrypted
  storage; operators without a TEE must protect the node's local paths, swap and file-level
  backups themselves (for example, `node.sh`'s `data.tar.gz` is not encrypted). They are: KV
  ingress staging (`TempFileSystemStage`, a `NamedTempFile` in the system temp directory,
  `tinycloud-node-server/src/storage/file_system.rs`); the SQL and DuckDB working databases and
  WAL files under `{datadir}/sql` and `{datadir}/duckdb`, and the hydration staging files a cold
  read writes beside them (`CacheFileSink` in `database_artifacts.rs`, `sql/service.rs`,
  `sql/database.rs`, `duckdb/database.rs`).
- **Columns:** `payload_encoding` and `delta_encoding` (SMALLINT, `NULL` = legacy plaintext; §5)
  and `manifest` (BLOB/BYTEA, `NULL` = no tag), migration
  `m20261107_010000_artifact_payload_encoding`. Each encoding is written with its part: a full
  save sets `payload_encoding` and clears the delta with its `delta_encoding`; a delta save sets
  `delta_encoding` only, so a legacy checkpoint can carry a sealed delta. Every save rewrites
  `manifest`.
- **Plaintext metadata:** `size_bytes`, `checkpoint_size_bytes`, `delta_size_bytes` and the three
  content hashes stay those of the plaintext database file. They are part of the identity (§4),
  and quota (`SqlSizes`) and the SQL growth check read them unchanged. Accepted residual: as
  before, anyone who can read the table sees each database's size and content hash.
- **Identity:** checkpoint `SqlCheckpoint { service, space, name, checkpoint_content_hash,
  checkpoint_size_bytes }`; delta `SqlWal { service, space, name, revision, checkpoint_content_hash,
  delta_content_hash }`, where `revision` is the row revision the delta was written at (always the
  row's current revision). A part moved to another row, space, name, revision or checkpoint is
  an integrity failure.
- **Manifest (what the row holds, authenticated):** the part identities alone don't say which
  parts a row must have. A checkpoint opens whatever the revision and whether or not a delta
  belongs with it, so someone who can write the table could drop a sealed delta (clear the delta
  columns, reset the unkeyed `content_hash` and `size_bytes`) and a cold read would serve the
  checkpoint alone, silently losing committed rows. So every sealed save also stores a tag in
  `manifest`: a TCE1 seal of an empty plaintext under the space's current data key with
  `SqlManifest { service, space, name, revision, content_hash, size_bytes, checkpoint:
  (checkpoint_content_hash, checkpoint_size_bytes, payload_encoding), delta: None | Some(
  (delta_content_hash, delta_size_bytes, delta_encoding)) }` (§4). That is a keyed MAC over the
  row's manifest, 80 bytes, naming its data key in its header like any sealed part, so it survives
  key rotation. A full save writes it with `delta: None`, a delta save with the delta; both
  rewrite it in the same `UPDATE` as the parts. Every read (`read_chunks`, and `open_row` for the
  offline tool) checks it before any part reaches the sink: a dropped or added delta, a part or
  metadata from another revision, a changed revision, or a changed encoding fails as integrity
  (`AtRestIntegrity { part: "manifest" }`, 500), never a partial read. Unknown or invalid
  encoding columns keep their own errors. Mode `off` writes no tag and clears it (its writes stay
  plaintext and need no key), so a row without a tag is accepted only if it has no sealed part, or
  if its only sealed part is a checkpoint under a delta mode `off` wrote; a row with any other
  sealed part and no tag fails as integrity.
  **Not protected:** a whole-row rollback, i.e. replacing the row with an older, valid,
  self-consistent snapshot of itself (parts, metadata and tag all from the same earlier
  revision), opens. So do rows with no tag: legacy parts are unauthenticated, as in §5, including
  a delta written in mode `off` over a sealed checkpoint (`strict` refuses that legacy delta).
- **Stored length and reads:** a TCE1 part stores exactly `ciphertext_len(size)` bytes. The
  streamed read slices the stored bytes (`substr`, 4 MiB) and opens them one 64 KiB segment at a
  time (`SegmentOpener`); the last slice of a sealed part asks for one byte past that length, so
  bytes appended to the part, or a part cut short, fail as integrity. The content hashes are
  checked over the plaintext, and sinks receive plaintext, so the cache sink still checks the
  SQLite/DuckDB file header. At most one segment is buffered beyond what the sink keeps.
- **Writes:** mode `off` stores plaintext exactly as before. Any other mode seals with
  `provider.current_key(space)` or fails (`AtRestUnavailable`), never plaintext. `current_key`
  runs before the SQLite writer lock, since it may create the space's key; sealing runs in
  `spawn_blocking`.
- **Errors:** keys locked, missing or the encrypt gate closed → 503 (`SqlError::Unavailable`,
  `DuckDbError::Unavailable`). `UnknownKey`, a malformed header, a header length that disagrees
  with the row, a stored length that disagrees with it, a manifest tag that doesn't match the row
  (or is missing where one is required), and any AEAD failure → 500 integrity; `Unsupported`
  (header or column `2..=9`) → 500 "upgrade the node"; a legacy part in `strict` → 500. A sealed
  part whose column says `NULL` fails the manifest check; it is never served.
- **Accepted residual (legacy injection in `encrypt`):** someone who can write the table can
  replace a row with legacy plaintext parts and no tag (any content, with matching hashes), and
  `encrypt` serves it, as it serves any legacy row. `strict` (after the backfill) refuses it.
- **Offline tool:** `tinycloud-sql-identity offline-fingerprint` has no keys and refuses sealed
  rows (`database_migration::offline_inventory` takes the provider). `open_row` checks the
  manifest tag first, like a streamed read.
- **Rollback:** a build without this change ignores the columns. It cannot hydrate a sealed part
  (the file-header check fails), and a save it makes over a sealed row without reading it
  (DuckDB `import_db`) leaves `payload_encoding = 1` on plaintext and a `manifest` tag for the
  previous contents, which this build then refuses as integrity. Roll back below this change only
  with no sealed rows; a row an older build overwrote that way needs its encoding columns and
  `manifest` set back to `NULL`.
