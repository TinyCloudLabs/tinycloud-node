//! TC-887 S3b: the FileSystem block store with encryption at rest.

use super::*;
use crate::config::AtRestMode;
use crate::storage::sealed::{AtRestSource, AtRestView};
use futures::io::AsyncReadExt as _;
use parking_lot::RwLock;
use rocket::http::Status;
use std::sync::Arc;
use tinycloud_core::at_rest::{ciphertext_len, DekId, FixedKeyProvider, SEGMENT_LEN};

const SEG: usize = SEGMENT_LEN;
const MARKER: &[u8] = b"TC887-FS-MARKER-plaintext-must-not-reach-disk";

/// An at-rest state the test can switch, as a recovery or restart would.
struct Switch(RwLock<AtRestView>);

impl AtRestSource for Switch {
    fn view(&self) -> AtRestView {
        self.0.read().clone()
    }
}

impl Switch {
    fn set(&self, v: AtRestView) {
        *self.0.write() = v;
    }
}

fn keys() -> FixedKeyProvider {
    FixedKeyProvider::new([9; 32])
}

fn view(mode: AtRestMode, encrypting: bool, keys: Option<FixedKeyProvider>) -> AtRestView {
    AtRestView {
        mode,
        encrypting,
        provider: keys.map(|k| Arc::new(k) as Arc<dyn DataKeyProvider>),
    }
}

fn encrypt() -> AtRestView {
    view(AtRestMode::Encrypt, true, Some(keys()))
}

fn space() -> SpaceId {
    "tinycloud:key:test:default".parse().unwrap()
}

async fn open_store(dir: &Path, v: AtRestView) -> (FileSystemStore, Arc<Switch>) {
    let mut store = FileSystemConfig::new(dir).open().await.unwrap();
    let switch = Arc::new(Switch(RwLock::new(v)));
    store.attach_at_rest(AtRestHandle::new(switch.clone()));
    store.create(&space()).await.unwrap();
    (store, switch)
}

fn value(n: usize) -> Vec<u8> {
    let mut v: Vec<u8> = (0..n).map(|i| (i * 7 % 251) as u8).collect();
    if n >= MARKER.len() {
        v[..MARKER.len()].copy_from_slice(MARKER);
    }
    v
}

async fn put_bytes(store: &FileSystemStore, data: &[u8]) -> Result<Hash, FileSystemStoreError> {
    let mut staged = HashBuffer::new(Vec::new());
    staged.write_all(data).await.unwrap();
    ImmutableWriteStore::<memory::MemoryStaging>::persist(store, &space(), staged).await
}

async fn put_file(store: &FileSystemStore, data: &[u8]) -> Result<Hash, FileSystemStoreError> {
    let mut staged = TempFileSystemStage.stage(&space()).await.unwrap();
    staged.write_all(data).await.unwrap();
    staged.flush().await.unwrap();
    ImmutableWriteStore::<TempFileSystemStage>::persist(store, &space(), staged).await
}

async fn read_all(store: &FileSystemStore, h: &Hash) -> Result<Option<Vec<u8>>, String> {
    let Some(content) = store.read(&space(), h).await.map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    let len = content.len();
    let mut out = Vec::new();
    let mut r = Box::pin(content);
    r.read_to_end(&mut out).await.map_err(|e| e.to_string())?;
    assert_eq!(
        out.len() as u64,
        len,
        "Content::len is the plaintext length"
    );
    Ok(Some(out))
}

fn sealed_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(tags) = std::fs::read_dir(dir.join(SEALED_DIR)) else {
        return out;
    };
    for tag in tags.flatten() {
        for obj in std::fs::read_dir(tag.path()).unwrap().flatten() {
            out.push(obj.path());
        }
    }
    out.sort();
    out
}

fn status(e: &FileSystemStoreError) -> Option<Status> {
    match e {
        FileSystemStoreError::AtRest(e) => Some(e.status()),
        _ => None,
    }
}

#[tokio::test]
async fn encrypt_mode_seals_both_staging_paths() {
    for (n, via_file) in [
        (10, false),
        (SEG + 5, false),
        (3 * SEG, true),
        (SEG - 1, true),
        (0, true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = open_store(dir.path(), encrypt()).await;
        let data = value(n);
        let h = if via_file {
            put_file(&store, &data).await.unwrap()
        } else {
            put_bytes(&store, &data).await.unwrap()
        };
        assert!(!store.get_path(&space(), &h).exists(), "no legacy copy");
        let files = sealed_files(dir.path());
        assert_eq!(files.len(), 1);
        let raw = std::fs::read(&files[0]).unwrap();
        assert_eq!(raw.len() as u64, ciphertext_len(n as u64).unwrap());
        assert!(
            !raw.windows(MARKER.len()).any(|w| w == MARKER),
            "plaintext on disk"
        );
        let rel = files[0]
            .strip_prefix(dir.path())
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(
            !rel.contains("tinycloud") && !rel.contains("key:test"),
            "{rel}"
        );
        assert_eq!(read_all(&store, &h).await.unwrap().unwrap(), data);
        assert!(store.contains(&space(), &h).await.unwrap());
        assert_eq!(store.total_size(&space()).await.unwrap(), Some(n as u64));
    }
}

#[tokio::test]
async fn sealed_ranges_use_plaintext_offsets_and_totals() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open_store(dir.path(), encrypt()).await;
    let n = 3 * SEG + 9;
    let data = value(n);
    let h = put_bytes(&store, &data).await.unwrap();
    let edges = [0, 1, SEG - 1, SEG, SEG + 1, 2 * SEG, n - 1];
    for &a in &edges {
        for &b in edges.iter().filter(|&&b| b >= a) {
            let spec = ByteRangeSpec::Inclusive {
                start: a as u64,
                end: b as u64,
            };
            match store.read_range(&space(), &h, spec).await.unwrap().unwrap() {
                RangeRead::Content {
                    total_size,
                    range,
                    content,
                } => {
                    assert_eq!(total_size, n as u64);
                    assert_eq!((range.start(), range.end()), (a as u64, b as u64));
                    assert_eq!(content.len(), (b - a + 1) as u64);
                    let mut out = Vec::new();
                    Box::pin(content).read_to_end(&mut out).await.unwrap();
                    assert_eq!(out, data[a..=b], "{a}..={b}");
                }
                RangeRead::Unsatisfiable { .. } => panic!("{a}..={b} unsatisfiable"),
            }
        }
    }
    assert!(matches!(
        store
            .read_range(&space(), &h, ByteRangeSpec::From { start: n as u64 })
            .await
            .unwrap()
            .unwrap(),
        RangeRead::Unsatisfiable { total_size } if total_size == n as u64
    ));
}

#[tokio::test]
async fn off_mode_writes_legacy_even_with_keys() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open_store(dir.path(), view(AtRestMode::Off, true, Some(keys()))).await;
    let data = value(100);
    let h = put_bytes(&store, &data).await.unwrap();
    assert!(store.get_path(&space(), &h).exists());
    assert!(sealed_files(dir.path()).is_empty());
    assert_eq!(read_all(&store, &h).await.unwrap().unwrap(), data);
}

#[tokio::test]
async fn legacy_reads_in_encrypt_and_is_refused_in_strict() {
    let dir = tempfile::tempdir().unwrap();
    let (store, switch) = open_store(dir.path(), AtRestView::off()).await;
    let data = value(SEG + 1);
    let h = put_bytes(&store, &data).await.unwrap();

    switch.set(encrypt());
    assert_eq!(read_all(&store, &h).await.unwrap().unwrap(), data);
    assert!(matches!(
        store
            .read_range(&space(), &h, ByteRangeSpec::Suffix { length: 3 })
            .await
            .unwrap(),
        Some(RangeRead::Content { .. })
    ));

    switch.set(view(AtRestMode::Strict, true, Some(keys())));
    for e in [
        store.read(&space(), &h).await.map(|_| ()).unwrap_err(),
        store
            .read_range(&space(), &h, ByteRangeSpec::From { start: 0 })
            .await
            .map(|_| ())
            .unwrap_err(),
    ] {
        assert!(
            matches!(
                e,
                FileSystemStoreError::AtRest(AtRestStoreError::LegacyRefused)
            ),
            "{e}"
        );
        assert_eq!(status(&e), Some(Status::InternalServerError));
    }
    assert!(!store.contains(&space(), &h).await.unwrap());
}

/// A legacy copy never suppresses the sealed write in encrypt mode.
#[tokio::test]
async fn a_legacy_copy_does_not_suppress_the_sealed_write() {
    let dir = tempfile::tempdir().unwrap();
    let (store, switch) = open_store(dir.path(), AtRestView::off()).await;
    let data = value(500);
    let h = put_bytes(&store, &data).await.unwrap();
    switch.set(encrypt());
    assert_eq!(put_file(&store, &data).await.unwrap(), h);
    assert!(store.get_path(&space(), &h).exists());
    assert_eq!(sealed_files(dir.path()).len(), 1);
    // Reads now come from the sealed copy: removing the legacy file changes nothing.
    std::fs::remove_file(store.get_path(&space(), &h)).unwrap();
    assert_eq!(read_all(&store, &h).await.unwrap().unwrap(), data);
}

/// `contains` checks the name a write would use (INTERFACES §7): in encrypt
/// mode a legacy-only block does not count; once sealed it does.
#[tokio::test]
async fn contains_checks_the_name_a_write_would_use() {
    let dir = tempfile::tempdir().unwrap();
    let (store, switch) = open_store(dir.path(), AtRestView::off()).await;
    let data = value(300);
    let h = put_bytes(&store, &data).await.unwrap();
    assert!(store.contains(&space(), &h).await.unwrap());
    switch.set(encrypt());
    assert!(!store.contains(&space(), &h).await.unwrap(), "legacy only");
    put_bytes(&store, &data).await.unwrap();
    assert!(store.contains(&space(), &h).await.unwrap(), "sealed");
    switch.set(view(AtRestMode::Encrypt, false, Some(keys().locked())));
    let e = store.contains(&space(), &h).await.unwrap_err();
    assert_eq!(status(&e), Some(Status::ServiceUnavailable), "{e}");
}

/// Switching back to `off` with keys still reads sealed blocks; `off` with
/// locked keys answers 503 for a sealed-only block (it may exist but cannot
/// be named).
#[tokio::test]
async fn off_after_encrypt_reads_sealed_and_locked_off_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let (store, switch) = open_store(dir.path(), encrypt()).await;
    let data = value(SEG + 3);
    let h = put_bytes(&store, &data).await.unwrap();
    switch.set(view(AtRestMode::Off, false, Some(keys())));
    assert_eq!(read_all(&store, &h).await.unwrap().unwrap(), data);
    switch.set(view(AtRestMode::Off, false, Some(keys().locked())));
    let e = store.read(&space(), &h).await.map(|_| ()).unwrap_err();
    assert_eq!(status(&e), Some(Status::ServiceUnavailable), "{e}");
}

/// `strict` with locked keys serves nothing: sealed and legacy reads are 503.
#[tokio::test]
async fn strict_with_locked_keys_is_unavailable_for_legacy_and_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let (store, switch) = open_store(dir.path(), AtRestView::off()).await;
    let hl = put_bytes(&store, &value(40)).await.unwrap();
    switch.set(encrypt());
    let hs = put_bytes(&store, &value(41)).await.unwrap();
    switch.set(view(AtRestMode::Strict, false, Some(keys().locked())));
    for h in [hl, hs] {
        let e = store.read(&space(), &h).await.map(|_| ()).unwrap_err();
        assert_eq!(status(&e), Some(Status::ServiceUnavailable), "{e}");
        let e = store
            .read_range(&space(), &h, ByteRangeSpec::Suffix { length: 2 })
            .await
            .map(|_| ())
            .unwrap_err();
        assert_eq!(status(&e), Some(Status::ServiceUnavailable), "{e}");
    }
}

/// `From` and `Suffix` ranges at every segment edge (k·64 KiB ± 1, up to an
/// exact multiple) return the plaintext slice and plaintext totals, for both
/// staging paths.
#[tokio::test]
async fn from_and_suffix_ranges_match_the_plaintext_at_segment_edges() {
    for (n, via_file) in [
        (3 * SEG, false),
        (3 * SEG, true),
        (2 * SEG + 1, true),
        (2 * SEG - 1, false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = open_store(dir.path(), encrypt()).await;
        let data = value(n);
        let h = if via_file {
            put_file(&store, &data).await.unwrap()
        } else {
            put_bytes(&store, &data).await.unwrap()
        };
        let edges = [
            0,
            1,
            SEG - 1,
            SEG,
            SEG + 1,
            2 * SEG - 1,
            2 * SEG,
            2 * SEG + 1,
            n - 1,
        ];
        for &at in edges.iter().filter(|&&at| at < n) {
            for (spec, want) in [
                (ByteRangeSpec::From { start: at as u64 }, &data[at..]),
                (
                    ByteRangeSpec::Suffix {
                        length: (n - at) as u64,
                    },
                    &data[at..],
                ),
            ] {
                match store.read_range(&space(), &h, spec).await.unwrap().unwrap() {
                    RangeRead::Content {
                        total_size,
                        content,
                        ..
                    } => {
                        assert_eq!(total_size, n as u64);
                        let mut out = Vec::new();
                        Box::pin(content).read_to_end(&mut out).await.unwrap();
                        assert!(out == want, "n={n} {spec:?}");
                    }
                    RangeRead::Unsatisfiable { .. } => panic!("n={n} {spec:?} unsatisfiable"),
                }
            }
        }
    }
}

/// A sealed persist that fails at its final step (the space's sealed
/// directory is read-only) leaves no temporary file behind: not the sealed
/// temp, not the staged plaintext (file staging, in its own directory), and
/// no legacy copy.
#[tokio::test]
async fn a_failed_sealed_persist_leaves_no_temporary_files() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let staging = tempfile::tempdir().unwrap();
    let (store, _) = open_store(dir.path(), encrypt()).await;
    put_bytes(&store, b"creates the space's sealed directory")
        .await
        .unwrap();
    let first = sealed_files(dir.path());
    let tag_dir = first[0].parent().unwrap().to_path_buf();
    std::fs::set_permissions(&tag_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

    let data = value(SEG + 11);
    let mut staged = HashBuffer::new(TempFileStage::new(
        NamedTempFile::new_in(staging.path()).unwrap(),
    ));
    staged.write_all(&data).await.unwrap();
    staged.flush().await.unwrap();
    let via_file =
        ImmutableWriteStore::<TempFileSystemStage>::persist(&store, &space(), staged).await;
    let via_bytes = put_bytes(&store, &data).await;
    std::fs::set_permissions(&tag_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(via_file.is_err() && via_bytes.is_err());
    let staged_left: Vec<_> = std::fs::read_dir(staging.path())
        .unwrap()
        .flatten()
        .collect();
    assert!(staged_left.is_empty(), "{staged_left:?}");
    assert_eq!(
        sealed_files(dir.path()),
        first,
        "no temporary or partial files"
    );
    let h = tinycloud_core::hash::hash(&data);
    assert!(!store.get_path(&space(), &h).exists());
}

#[tokio::test]
async fn locked_keys_refuse_writes_and_sealed_reads_but_serve_legacy() {
    let dir = tempfile::tempdir().unwrap();
    let (store, switch) = open_store(dir.path(), AtRestView::off()).await;
    let legacy = value(64);
    let hl = put_bytes(&store, &legacy).await.unwrap();
    switch.set(encrypt());
    let sealed = value(65);
    let hs = put_bytes(&store, &sealed).await.unwrap();

    for locked in [
        view(AtRestMode::Encrypt, false, Some(keys().locked())),
        view(AtRestMode::Encrypt, true, Some(keys().locked())),
        view(AtRestMode::Encrypt, false, Some(keys())),
    ] {
        switch.set(locked);
        let e = put_bytes(&store, &value(66)).await.unwrap_err();
        assert_eq!(status(&e), Some(Status::ServiceUnavailable), "{e}");
    }
    switch.set(view(AtRestMode::Encrypt, false, Some(keys().locked())));
    assert_eq!(read_all(&store, &hl).await.unwrap().unwrap(), legacy);
    let e = store.read(&space(), &hs).await.map(|_| ()).unwrap_err();
    assert_eq!(status(&e), Some(Status::ServiceUnavailable), "{e}");
    let e = store
        .read_range(&space(), &hs, ByteRangeSpec::From { start: 0 })
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(status(&e), Some(Status::ServiceUnavailable), "{e}");
}

/// After a restart, sealed bytes are counted by tag; a locked node reports
/// legacy bytes only, and the first quota check after unlocking counts both.
#[tokio::test]
async fn quota_after_unlock_counts_legacy_and_sealed() {
    let dir = tempfile::tempdir().unwrap();
    {
        let (store, switch) = open_store(dir.path(), AtRestView::off()).await;
        put_bytes(&store, &value(1000)).await.unwrap();
        switch.set(encrypt());
        put_bytes(&store, &value(70_000)).await.unwrap();
        assert_eq!(store.total_size(&space()).await.unwrap(), Some(71_000));
    }
    // Restart: the boot scan sees 1000 legacy bytes and 70 000 sealed bytes
    // under a tag. No `create` (it would reset the legacy entry, as before).
    let switch = Arc::new(Switch(RwLock::new(view(
        AtRestMode::Encrypt,
        false,
        Some(keys().locked()),
    ))));
    let mut store = FileSystemConfig::new(dir.path()).open().await.unwrap();
    store.attach_at_rest(AtRestHandle::new(switch.clone()));
    assert_eq!(store.total_size(&space()).await.unwrap(), Some(1000));
    switch.set(encrypt());
    assert_eq!(store.total_size(&space()).await.unwrap(), Some(71_000));
    put_bytes(&store, &value(5)).await.unwrap();
    assert_eq!(store.total_size(&space()).await.unwrap(), Some(71_005));
}

#[tokio::test]
async fn tampered_swapped_or_unsupported_sealed_files_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open_store(dir.path(), encrypt()).await;
    let (a, b) = (
        value(SEG + 3),
        value(SEG + 3).into_iter().rev().collect::<Vec<_>>(),
    );
    let ha = put_bytes(&store, &a).await.unwrap();
    let hb = put_bytes(&store, &b).await.unwrap();
    let nk = keys().object_name_key().unwrap();
    let pa = store.sealed_path(&SealedName::new(&nk, &space(), &ha));
    let pb = store.sealed_path(&SealedName::new(&nk, &space(), &hb));

    // Swap the two objects (same space, same size): each name now holds the
    // other blob, bound to the other hash.
    let (ra, rb) = (std::fs::read(&pa).unwrap(), std::fs::read(&pb).unwrap());
    std::fs::write(&pa, &rb).unwrap();
    std::fs::write(&pb, &ra).unwrap();
    for h in [&ha, &hb] {
        let e = read_all(&store, h).await.unwrap_err();
        assert!(e.to_lowercase().contains("integrity"), "{e}");
    }

    // A flipped byte in the second segment: the first segment is served, then the stream fails.
    let mut t = ra.clone();
    t[64 + SEG + 16 + 1] ^= 1;
    std::fs::write(&pa, &t).unwrap();
    let content = store.read(&space(), &ha).await.unwrap().unwrap();
    let mut out = Vec::new();
    let err = Box::pin(content).read_to_end(&mut out).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        out.len() <= SEG,
        "only the authenticated segment was released"
    );

    // A later format generation: a hard error, never legacy.
    let mut v2 = ra.clone();
    v2[3] = b'2';
    v2[4] = 2;
    std::fs::write(&pa, &v2).unwrap();
    let e = store.read(&space(), &ha).await.map(|_| ()).unwrap_err();
    assert!(
        matches!(
            e,
            FileSystemStoreError::AtRest(AtRestStoreError::Unsupported(2))
        ),
        "{e}"
    );
    assert_eq!(status(&e), Some(Status::InternalServerError));
}

#[tokio::test]
async fn removing_a_sealed_block_drops_its_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open_store(dir.path(), encrypt()).await;
    let h = put_bytes(&store, &value(4096)).await.unwrap();
    assert_eq!(store.total_size(&space()).await.unwrap(), Some(4096));
    assert_eq!(store.remove(&space(), &h).await.unwrap(), Some(()));
    assert!(sealed_files(dir.path()).is_empty());
    assert_eq!(store.total_size(&space()).await.unwrap(), Some(0));
    assert_eq!(store.read(&space(), &h).await.unwrap().map(|_| ()), None);
}

#[tokio::test]
async fn the_current_key_rotates_without_breaking_old_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let (store, switch) = open_store(dir.path(), encrypt()).await;
    let old = value(300);
    let h_old = put_bytes(&store, &old).await.unwrap();
    switch.set(view(
        AtRestMode::Encrypt,
        true,
        Some(FixedKeyProvider::new([9; 32]).with_current(DekId::new(2))),
    ));
    let new = value(301);
    let h_new = put_bytes(&store, &new).await.unwrap();
    assert_eq!(read_all(&store, &h_old).await.unwrap().unwrap(), old);
    assert_eq!(read_all(&store, &h_new).await.unwrap().unwrap(), new);
}
