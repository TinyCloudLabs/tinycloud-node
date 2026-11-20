//! TC-3554: the node's identity root, sealed under a wrap key of the current
//! dstack KMS root and kept in the database (`root_wrap`, one row), so a
//! node whose identity root came from a historical KMS root epoch can boot
//! without fetching that epoch again.
//!
//! The seal is AES-256-GCM with a random 96-bit nonce; the blob is
//! `nonce || ciphertext || tag`. The AAD binds it to this format, the app and
//! the identity it must derive: `"tinycloud/root-wrap/v1" || app_id (20 raw
//! bytes) || baseline node DID (UTF-8)`.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    AeadCore, Aes256Gcm, Nonce,
};
use sea_orm::{ConnectionTrait, DbErr, Statement};
use sea_orm_migration::prelude::*;
use zeroize::Zeroizing;

/// The AAD's leading format label.
pub const AAD_LABEL: &[u8] = b"tinycloud/root-wrap/v1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

#[derive(DeriveIden)]
pub enum RootWrap {
    Table,
    Id,
    Wrapped,
    NodeDid,
    KmsRootEpoch,
    CreatedAt,
}

/// The stored row: the sealed root, the node DID it must derive and the KMS
/// root epoch it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedRoot {
    pub wrapped: Vec<u8>,
    pub node_did: String,
    pub kms_root_epoch: i32,
}

/// The seal or the blob is not authentic under this key and AAD. Carries no
/// detail on purpose: AES-GCM does not say why.
#[derive(Debug, thiserror::Error)]
#[error("the root_wrap blob does not open under this wrap key and AAD")]
pub struct UnsealError;

/// `"tinycloud/root-wrap/v1" || app_id || baseline_did`.
pub fn aad(app_id: &[u8; 20], baseline_did: &str) -> Vec<u8> {
    [AAD_LABEL, app_id, baseline_did.as_bytes()].concat()
}

/// Seal `root` under `wrap_key` with a fresh random nonce.
pub fn seal(wrap_key: &[u8; 32], aad: &[u8], root: &[u8]) -> Vec<u8> {
    seal_with_nonce(
        wrap_key,
        &Aes256Gcm::generate_nonce(&mut OsRng).into(),
        aad,
        root,
    )
}

fn seal_with_nonce(
    wrap_key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    root: &[u8],
) -> Vec<u8> {
    let ciphertext = Aes256Gcm::new(wrap_key.into())
        .encrypt(&Nonce::from(*nonce), Payload { msg: root, aad })
        .expect("AES-GCM encryption of a 32-byte root cannot fail");
    [nonce.as_slice(), &ciphertext].concat()
}

/// Open a blob from [`seal`]. Any tampering, another key or another AAD is
/// an [`UnsealError`].
pub fn unseal(
    wrap_key: &[u8; 32],
    aad: &[u8],
    wrapped: &[u8],
) -> Result<Zeroizing<Vec<u8>>, UnsealError> {
    if wrapped.len() < NONCE_LEN + TAG_LEN {
        return Err(UnsealError);
    }
    let Some((nonce, ciphertext)) = wrapped.split_first_chunk::<NONCE_LEN>() else {
        return Err(UnsealError);
    };
    Aes256Gcm::new(wrap_key.into())
        .decrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| UnsealError)
}

/// `CREATE TABLE IF NOT EXISTS root_wrap`. Shared by the migration and the
/// boot path, which needs the table before the identity check, ahead of
/// every other migration.
pub fn create_table() -> TableCreateStatement {
    Table::create()
        .table(RootWrap::Table)
        .if_not_exists()
        .col(
            ColumnDef::new(RootWrap::Id)
                .small_integer()
                .not_null()
                .primary_key(),
        )
        .col(ColumnDef::new(RootWrap::Wrapped).binary().not_null())
        .col(ColumnDef::new(RootWrap::NodeDid).text().not_null())
        .col(ColumnDef::new(RootWrap::KmsRootEpoch).integer().not_null())
        .col(
            ColumnDef::new(RootWrap::CreatedAt)
                .timestamp_with_time_zone()
                .not_null()
                .default(Expr::current_timestamp()),
        )
        .check(Expr::col(RootWrap::Id).eq(1))
        .to_owned()
}

/// Create the `root_wrap` table if it does not exist.
pub async fn ensure_table<C: ConnectionTrait>(conn: &C) -> Result<(), DbErr> {
    let backend = conn.get_database_backend();
    conn.execute(backend.build(&create_table())).await?;
    Ok(())
}

/// The stored row, if any.
pub async fn read<C: ConnectionTrait>(conn: &C) -> Result<Option<WrappedRoot>, DbErr> {
    let backend = conn.get_database_backend();
    let Some(row) = conn
        .query_one(Statement::from_string(
            backend,
            "SELECT wrapped, node_did, kms_root_epoch FROM root_wrap WHERE id = 1",
        ))
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(WrappedRoot {
        wrapped: row.try_get("", "wrapped")?,
        node_did: row.try_get("", "node_did")?,
        kms_root_epoch: row.try_get("", "kms_root_epoch")?,
    }))
}

/// Store `root` unless a row exists. The first writer wins; every caller
/// re-reads with [`read`] and uses the stored row.
pub async fn insert_if_absent<C: ConnectionTrait>(
    conn: &C,
    root: &WrappedRoot,
) -> Result<(), DbErr> {
    let backend = conn.get_database_backend();
    let insert = Query::insert()
        .into_table(RootWrap::Table)
        .columns([
            RootWrap::Id,
            RootWrap::Wrapped,
            RootWrap::NodeDid,
            RootWrap::KmsRootEpoch,
        ])
        .values_panic([
            1.into(),
            root.wrapped.clone().into(),
            root.node_did.clone().into(),
            root.kms_root_epoch.into(),
        ])
        .on_conflict(OnConflict::column(RootWrap::Id).do_nothing().to_owned())
        .to_owned();
    conn.execute(backend.build(&insert)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ConnectOptions, Database};

    const WRAP_KEY: [u8; 32] = [0x42; 32];
    const APP_ID: [u8; 20] = [0x35; 20];
    /// The node DID of `ROOT` (docs/tc-3554-kms-epoch-fetch.md test vectors).
    const DID: &str = "did:key:z6Mki14g4VZeY9fra5wUt8m5DmYkmAfWDtUKecu65Kd1uWU9";
    const ROOT: &str = "bbeb1e02123fe7cfab8471656ab89eff4d0b517fabdd457aa624942d1d5e0b02";

    fn root() -> Vec<u8> {
        hex::decode(ROOT).unwrap()
    }

    /// Known answer, computed independently with Python `cryptography`
    /// (`AESGCM(key).encrypt(nonce, root, aad)`, nonce prepended).
    #[test]
    fn seal_matches_the_known_answer_and_unseals() {
        let aad = aad(&APP_ID, DID);
        assert_eq!(
            aad,
            [
                b"tinycloud/root-wrap/v1".as_slice(),
                &[0x35; 20],
                DID.as_bytes()
            ]
            .concat()
        );
        let wrapped = seal_with_nonce(&WRAP_KEY, &[0x24; 12], &aad, &root());
        assert_eq!(
            hex::encode(&wrapped),
            "242424242424242424242424ae7ada43fbf921f18d6c53cfd78a0d5921f0620f1d761517168058774b9bec114debf74a40d7d297e3bc27adf903d1f3"
        );
        assert_eq!(*unseal(&WRAP_KEY, &aad, &wrapped).unwrap(), root());
    }

    #[test]
    fn seal_uses_a_fresh_nonce() {
        let aad = aad(&APP_ID, DID);
        let first = seal(&WRAP_KEY, &aad, &root());
        let second = seal(&WRAP_KEY, &aad, &root());
        assert_ne!(first[..NONCE_LEN], second[..NONCE_LEN]);
        assert_eq!(*unseal(&WRAP_KEY, &aad, &first).unwrap(), root());
        assert_eq!(*unseal(&WRAP_KEY, &aad, &second).unwrap(), root());
    }

    #[test]
    fn a_tampered_blob_does_not_open() {
        let aad = aad(&APP_ID, DID);
        let wrapped = seal(&WRAP_KEY, &aad, &root());
        for at in [0, NONCE_LEN, wrapped.len() - 1] {
            let mut tampered = wrapped.clone();
            tampered[at] ^= 1;
            assert!(unseal(&WRAP_KEY, &aad, &tampered).is_err(), "byte {at}");
        }
        for len in [0, NONCE_LEN + TAG_LEN - 1, wrapped.len() - 1] {
            assert!(unseal(&WRAP_KEY, &aad, &wrapped[..len]).is_err(), "{len}");
        }
        assert!(unseal(&[0x43; 32], &aad, &wrapped).is_err());
    }

    #[test]
    fn another_aad_does_not_open() {
        let wrapped = seal(&WRAP_KEY, &aad(&APP_ID, DID), &root());
        let other_did = "did:key:z6MkgWpiYdQV8pAr3dtHLdQsoZR3wF5wsS7fpkzAuX6q1PZj";
        for other in [
            aad(&[0x36; 20], DID),
            aad(&APP_ID, other_did),
            [
                b"tinycloud/root-wrap/v2".as_slice(),
                &APP_ID,
                DID.as_bytes(),
            ]
            .concat(),
            Vec::new(),
        ] {
            assert!(unseal(&WRAP_KEY, &other, &wrapped).is_err());
        }
    }

    fn row(wrapped: Vec<u8>) -> WrappedRoot {
        WrappedRoot {
            wrapped,
            node_did: DID.into(),
            kms_root_epoch: 0,
        }
    }

    #[tokio::test]
    async fn the_table_holds_one_row_and_the_first_insert_wins() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        ensure_table(&db).await.unwrap();
        ensure_table(&db).await.unwrap();
        assert_eq!(read(&db).await.unwrap(), None);
        insert_if_absent(&db, &row(vec![1; 60])).await.unwrap();
        insert_if_absent(&db, &row(vec![2; 60])).await.unwrap();
        assert_eq!(read(&db).await.unwrap(), Some(row(vec![1; 60])));
        // The CHECK keeps it to the one row the boot path reads.
        let other_id = db
            .execute_unprepared(
                "INSERT INTO root_wrap (id, wrapped, node_did, kms_root_epoch) \
                 VALUES (2, x'00', 'did:key:z', 0)",
            )
            .await;
        assert!(other_id.is_err());
    }

    /// Two boots racing on one database both end up with the same stored
    /// blob, whichever inserted first.
    #[tokio::test]
    async fn concurrent_inserts_agree_on_one_blob() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite:{}?mode=rwc", dir.path().join("caps.db").display());
        let connect = || async {
            let mut options = ConnectOptions::new(url.clone());
            options.max_connections(1);
            Database::connect(options).await.unwrap()
        };
        let (first, second) = (connect().await, connect().await);
        ensure_table(&first).await.unwrap();
        let aad = aad(&APP_ID, DID);
        let (a, b) = (
            row(seal(&WRAP_KEY, &aad, &root())),
            row(seal(&WRAP_KEY, &aad, &root())),
        );
        assert_ne!(a, b);
        let boot = |conn: sea_orm::DatabaseConnection, mine: WrappedRoot| async move {
            ensure_table(&conn).await.unwrap();
            insert_if_absent(&conn, &mine).await.unwrap();
            read(&conn).await.unwrap().unwrap()
        };
        let (seen_first, seen_second) =
            tokio::join!(boot(first, a.clone()), boot(second, b.clone()));
        assert_eq!(seen_first, seen_second);
        assert!(seen_first == a || seen_first == b);
        assert_eq!(
            *unseal(&WRAP_KEY, &aad, &seen_first.wrapped).unwrap(),
            root()
        );
    }

    #[tokio::test]
    async fn postgres_concurrent_inserts_agree_on_one_blob() {
        let Some(schema) =
            crate::test_support::PostgresTestSchema::new("postgres_root_wrap_concurrent_inserts")
                .await
        else {
            return;
        };
        let aad = aad(&APP_ID, DID);
        let rows: Vec<_> = (0..8)
            .map(|_| row(seal(&WRAP_KEY, &aad, &root())))
            .collect();
        let mut boots = Vec::new();
        for mine in rows.clone() {
            let conn = schema.connect(1).await;
            boots.push(tokio::spawn(async move {
                insert_if_absent(&conn, &mine).await.unwrap();
                read(&conn).await.unwrap().unwrap()
            }));
        }
        let mut seen = Vec::new();
        for boot in boots {
            seen.push(boot.await.unwrap());
        }
        assert!(seen.windows(2).all(|pair| pair[0] == pair[1]));
        assert!(rows.contains(&seen[0]));
    }
}
