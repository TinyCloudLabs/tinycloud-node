use super::*;
use futures::io::{AsyncReadExt, Cursor};
use rocket::http::Status;
use tinycloud_core::at_rest::{ciphertext_len, DekId, FixedKeyProvider, SEGMENT_LEN};

const SEG: usize = SEGMENT_LEN;

fn space() -> SpaceId {
    "tinycloud:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266:default"
        .parse()
        .unwrap()
}

fn view(mode: AtRestMode, encrypting: bool, provider: Option<FixedKeyProvider>) -> AtRestView {
    AtRestView {
        mode,
        encrypting,
        provider: provider.map(|p| Arc::new(p) as Arc<dyn DataKeyProvider>),
    }
}

fn keys() -> FixedKeyProvider {
    FixedKeyProvider::new([7; 32])
}

fn bytes(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

async fn sealed(p: &FixedKeyProvider, data: &[u8]) -> (Hash, Vec<u8>) {
    let hash = tinycloud_core::hash::hash(data);
    let key = p.current_key(&space().to_string()).await.unwrap();
    (
        hash,
        seal_vec(key, &space(), &hash, data.to_vec()).await.unwrap(),
    )
}

async fn read_to_end<R: AsyncRead + Unpin>(mut r: R) -> (Vec<u8>, Option<std::io::Error>) {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match r.read(&mut buf).await {
            Ok(0) => return (out, None),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => return (out, Some(e)),
        }
    }
}

#[tokio::test]
async fn write_target_follows_the_mode_and_gate() {
    let s = space();
    let h = tinycloud_core::hash::hash(b"x");
    // off writes legacy even when keys exist.
    let off = view(AtRestMode::Off, true, Some(keys()));
    assert!(matches!(
        write_target(&off, &s, &h).await,
        Ok(WriteTarget::Legacy)
    ));
    // encrypt with the gate open seals under the current key and the sealed name.
    let on = view(AtRestMode::Encrypt, true, Some(keys()));
    match write_target(&on, &s, &h).await.unwrap() {
        WriteTarget::Sealed { name, key } => {
            let nk = keys().object_name_key().unwrap();
            assert_eq!(name, SealedName::new(&nk, &s, &h));
            assert_eq!(
                name.key(),
                tinycloud_core::at_rest::sealed_object_name(&nk, &s.to_string(), &h)
            );
            assert_eq!(key.id(), DekId::new(1));
        }
        WriteTarget::Legacy => panic!("encrypt mode wrote legacy"),
    }
    // encrypt with the gate closed, keys missing or locked: 503, never plaintext.
    for v in [
        view(AtRestMode::Encrypt, false, Some(keys())),
        view(AtRestMode::Strict, false, None),
        view(AtRestMode::Encrypt, true, None),
        view(AtRestMode::Encrypt, true, Some(keys().locked())),
    ] {
        let e = write_target(&v, &s, &h).await.err().expect("must refuse");
        assert_eq!(e.status(), Status::ServiceUnavailable, "{e}");
    }
}

#[test]
fn read_plan_follows_the_mode_and_key_state() {
    let s = space();
    let h = tinycloud_core::hash::hash(b"x");
    assert!(matches!(
        read_plan(&AtRestView::off(), &s, &h),
        Ok(ReadPlan::Legacy)
    ));
    assert!(matches!(
        read_plan(&view(AtRestMode::Off, false, Some(keys())), &s, &h),
        Ok(ReadPlan::SealedThenLegacy { .. })
    ));
    assert!(matches!(
        read_plan(&view(AtRestMode::Encrypt, true, Some(keys())), &s, &h),
        Ok(ReadPlan::SealedThenLegacy { .. })
    ));
    assert!(matches!(
        read_plan(
            &view(AtRestMode::Encrypt, false, Some(keys().locked())),
            &s,
            &h
        ),
        Ok(ReadPlan::LegacyWhileLocked)
    ));
    assert!(matches!(
        read_plan(&view(AtRestMode::Strict, true, Some(keys())), &s, &h),
        Ok(ReadPlan::Sealed { .. })
    ));
    for v in [
        view(AtRestMode::Strict, false, Some(keys().locked())),
        view(AtRestMode::Strict, false, None),
    ] {
        let e = read_plan(&v, &s, &h)
            .err()
            .expect("strict without keys refuses");
        assert_eq!(e.status(), Status::ServiceUnavailable);
    }
}

#[tokio::test]
async fn sealed_objects_round_trip_with_plaintext_length() {
    let p = keys();
    for n in [0, 1, SEG - 1, SEG, SEG + 1, 2 * SEG + 7] {
        let data = bytes(n);
        let (h, ct) = sealed(&p, &data).await;
        assert_eq!(ct.len() as u64, ciphertext_len(n as u64).unwrap());
        let len = ct.len() as u64;
        let content = open_sealed(&p, &space(), &h, Cursor::new(ct), len)
            .await
            .unwrap();
        assert_eq!(content.len(), n as u64);
        let (out, err) = read_to_end(content).await;
        assert!(err.is_none());
        assert_eq!(out, data);
    }
}

#[tokio::test]
async fn sealed_open_fails_closed() {
    let p = keys();
    let data = bytes(SEG + 10);
    let (h, ct) = sealed(&p, &data).await;
    let s = space();
    let len = ct.len() as u64;

    // Stored size differs from the header: refused before any byte.
    let e = open_sealed(
        &p,
        &s,
        &h,
        Cursor::new(ct[..ct.len() - 1].to_vec()),
        len - 1,
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(e, AtRestStoreError::Integrity(_)), "{e}");

    // A later generation: unsupported, a hard error.
    let mut v2 = ct.clone();
    v2[3] = b'2';
    v2[4] = 2;
    let e = open_sealed(&p, &s, &h, Cursor::new(v2), len)
        .await
        .err()
        .unwrap();
    assert!(matches!(e, AtRestStoreError::Unsupported(2)), "{e}");
    assert_eq!(e.status(), Status::InternalServerError);

    // Header names a key the space never had.
    let newer = FixedKeyProvider::new([7; 32]).with_current(DekId::new(2));
    let (h2, ct2) = sealed(&newer, &data).await;
    let len2 = ct2.len() as u64;
    let e = open_sealed(&p, &s, &h2, Cursor::new(ct2), len2)
        .await
        .err()
        .unwrap();
    assert!(matches!(e, AtRestStoreError::Integrity(_)), "{e}");

    // Locked keys: 503.
    let e = open_sealed(&keys().locked(), &s, &h, Cursor::new(ct.clone()), len)
        .await
        .err()
        .unwrap();
    assert_eq!(e.status(), Status::ServiceUnavailable);

    // Bound to the content hash: another hash's name cannot serve it.
    let other = tinycloud_core::hash::hash(b"other");
    let content = open_sealed(&p, &s, &other, Cursor::new(ct.clone()), len)
        .await
        .unwrap();
    let (out, err) = read_to_end(content).await;
    assert!(out.is_empty());
    assert_eq!(err.unwrap().kind(), std::io::ErrorKind::InvalidData);

    // Not TCE at all (a legacy blob under a sealed name): never served as plaintext.
    let e = open_sealed(&p, &s, &h, Cursor::new(data.clone()), data.len() as u64)
        .await
        .err()
        .unwrap();
    assert!(matches!(e, AtRestStoreError::Integrity(_)), "{e}");
}

/// The header's length is unverified until a segment decrypts. A forged
/// length can mis-state the total, but the body aborts and yields no bytes
/// that were not authenticated.
#[tokio::test]
async fn forged_header_length_aborts_without_extra_bytes() {
    let p = keys();
    let data = bytes(3 * SEG);
    let (h, ct) = sealed(&p, &data).await;
    for forged in [SEG as u64, 5 * SEG as u64, 1] {
        let mut f = ct.clone();
        f[12..20].copy_from_slice(&forged.to_be_bytes());
        // Pad or cut so the stored size matches the forged header.
        f.resize(ciphertext_len(forged).unwrap() as usize, 0xAB);
        let len = f.len() as u64;
        let content = open_sealed(&p, &space(), &h, Cursor::new(f), len)
            .await
            .unwrap();
        assert_eq!(
            content.len(),
            forged,
            "the total is the (unverified) header's"
        );
        let (out, err) = read_to_end(content).await;
        assert!(
            out.is_empty(),
            "forged {forged}: {} bytes released",
            out.len()
        );
        assert_eq!(err.unwrap().kind(), std::io::ErrorKind::InvalidData);
    }
}

#[tokio::test]
async fn sealed_ranges_equal_plaintext_slices() {
    let p = keys();
    let n = 3 * SEG + 5;
    let data = bytes(n);
    let (h, ct) = sealed(&p, &data).await;
    let s = space();
    let len = ct.len() as u64;
    let edges = [0, 1, SEG - 1, SEG, SEG + 1, 2 * SEG, n - 1];
    for &a in &edges {
        for &b in &edges {
            if a > b {
                continue;
            }
            let spec = ByteRangeSpec::Inclusive {
                start: a as u64,
                end: b as u64,
            };
            let plan = plan_range(&p, &s, &ct[..HEADER_LEN], len, spec)
                .await
                .unwrap();
            let r = plan.range.expect("satisfiable");
            assert_eq!(plan.plaintext_len(), n as u64);
            let span = ct[r.ciphertext_start() as usize..=r.ciphertext_end() as usize].to_vec();
            let (out, err) = read_to_end(plan.reader(&s, &h, r, Cursor::new(span)).unwrap()).await;
            assert!(err.is_none());
            assert_eq!(out, data[a..=b], "{a}..={b}");
        }
    }
    let plan = plan_range(
        &p,
        &s,
        &ct[..HEADER_LEN],
        len,
        ByteRangeSpec::From { start: n as u64 },
    )
    .await
    .unwrap();
    assert!(plan.range.is_none(), "416");
    assert_eq!(
        plan.plaintext_len(),
        n as u64,
        "416 total is the plaintext length"
    );
}

#[tokio::test]
async fn sealed_files_stream_to_the_same_envelope() {
    let p = keys();
    let s = space();
    let dir = tempfile::tempdir().unwrap();
    let data = bytes(2 * SEG + 123);
    let h = tinycloud_core::hash::hash(&data);
    let src = dir.path().join("staged");
    std::fs::write(&src, &data).unwrap();
    let key = p.current_key(&s.to_string()).await.unwrap();

    let out = seal_file(&key, &s, &h, &src, data.len() as u64)
        .await
        .unwrap();
    assert_eq!(
        out.path().parent(),
        Some(dir.path()),
        "sealed beside the staged file"
    );
    let ct = std::fs::read(out.path()).unwrap();
    let len = ct.len() as u64;
    let (plain, err) =
        read_to_end(open_sealed(&p, &s, &h, Cursor::new(ct), len).await.unwrap()).await;
    assert!(err.is_none());
    assert_eq!(plain, data);

    // A staged file that is not the declared length is refused.
    assert!(seal_file(&key, &s, &h, &src, data.len() as u64 + 1)
        .await
        .is_err());
    assert!(seal_file(&key, &s, &h, &src, data.len() as u64 - 1)
        .await
        .is_err());
}

#[test]
fn boot_scan_classifies_names() {
    let s = space();
    assert_eq!(
        scanned_object(&format!("{s}/QU63=")),
        ScannedObject::Legacy(s)
    );
    assert_eq!(scanned_object("v1/tagA/obj"), ScannedObject::Sealed("tagA"));
    for other in [
        "_tc/at-rest/dek-x-1.json",
        "_tc/at-rest/ark-1.sealed",
        "v1/tagA",
        "v1//obj",
        "v1/tagA/obj/extra",
        "not-a-space/obj",
        "loose",
    ] {
        assert_eq!(scanned_object(other), ScannedObject::Other, "{other}");
    }
}

#[test]
fn space_tags_need_unlocked_keys() {
    let s = space();
    assert_eq!(
        space_tag_of(&view(AtRestMode::Encrypt, false, Some(keys().locked())), &s),
        None
    );
    assert_eq!(space_tag_of(&AtRestView::off(), &s), None);
    let nk = keys().object_name_key().unwrap();
    assert_eq!(
        space_tag_of(&view(AtRestMode::Off, false, Some(keys())), &s),
        Some(space_tag(&nk, &s.to_string()))
    );
}

/// At-rest causes answer 503 (retry may help) or 500 (operator must act) on
/// the KV GET routes and on `/invoke`, reads and writes alike; anything else
/// keeps its old mapping.
#[test]
fn at_rest_causes_map_to_503_or_500_on_kv_reads_and_invoke() {
    use crate::storage::{file_system::FileSystemStoreError, s3::S3StoreError};
    use tinycloud_core::{storage::either::EitherError, TxStoreError};
    let store_err = |e: AtRestStoreError, s3: bool| {
        if s3 {
            EitherError::A(S3StoreError::AtRest(e))
        } else {
            EitherError::B(FileSystemStoreError::AtRest(e))
        }
    };
    let cases = || {
        [
            (
                AtRestStoreError::Unavailable("locked"),
                Status::ServiceUnavailable,
            ),
            (
                AtRestStoreError::KeyStore("store_unavailable"),
                Status::ServiceUnavailable,
            ),
            (
                AtRestStoreError::KeyInconsistent("inconsistent"),
                Status::InternalServerError,
            ),
            (
                AtRestStoreError::Integrity("x"),
                Status::InternalServerError,
            ),
            (
                AtRestStoreError::Unsupported(2),
                Status::InternalServerError,
            ),
            (AtRestStoreError::LegacyRefused, Status::InternalServerError),
            (
                AtRestStoreError::Internal("sealing task failed"),
                Status::InternalServerError,
            ),
        ]
    };
    for s3 in [true, false] {
        for (e, want) in cases() {
            let what = e.to_string();
            assert_eq!(
                crate::routes::kv_read_failure(EitherError::B(store_err(e, s3))).0,
                want,
                "kv read: {what}"
            );
        }
        for (e, want) in cases() {
            let what = e.to_string();
            let read = TxStoreError::StoreRead(store_err(e, s3));
            assert_eq!(
                crate::routes::at_rest_invoke_status(&read),
                Some(want),
                "invoke read: {what}"
            );
        }
        for (e, want) in cases() {
            let what = e.to_string();
            let write = TxStoreError::StoreWrite(store_err(e, s3));
            assert_eq!(
                crate::routes::at_rest_invoke_status(&write),
                Some(want),
                "invoke write: {what}"
            );
        }
    }
    let other = EitherError::B(EitherError::B(FileSystemStoreError::Io(
        std::io::Error::other("disk"),
    )));
    assert_eq!(
        crate::routes::kv_read_failure(other).0,
        Status::InternalServerError
    );
    let io = TxStoreError::StoreRead(EitherError::B(FileSystemStoreError::Io(
        std::io::Error::other("disk"),
    )));
    assert_eq!(crate::routes::at_rest_invoke_status(&io), None);
}

/// Key-store failures answer with a reason code only; backend detail stays
/// in the server log. A stored key that does not unwrap is a 500.
#[test]
fn key_store_failures_carry_reason_codes_only() {
    use tinycloud_core::sea_orm::DbErr;
    let db = AtRestStoreError::from(DataKeyError::Backend(Box::new(DbErr::Custom(
        "SELECT secret_table_detail".into(),
    ))));
    assert_eq!(db.status(), Status::ServiceUnavailable);
    assert!(!db.to_string().contains("secret_table_detail"), "{db}");
    let unwrap = AtRestStoreError::from(DataKeyError::Backend(Box::new(std::io::Error::other(
        "aead tag mismatch detail",
    ))));
    assert_eq!(unwrap.status(), Status::InternalServerError);
    assert!(!unwrap.to_string().contains("detail"), "{unwrap}");
    assert_eq!(
        AtRestStoreError::from(DataKeyError::NotPrepared).status(),
        Status::ServiceUnavailable
    );
}
