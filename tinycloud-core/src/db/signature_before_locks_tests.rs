//! TC-2986 (E): `/delegate` and `/revoke` check the signature before they
//! take any lock. A badly signed request is refused at once, even while
//! another writer holds the write order of every space it names.
use super::*;
use crate::storage::memory::MemoryStore;
use tinycloud_auth::{
    authorization::{TinyCloudDelegation, TinyCloudRevocation},
    resolver::DID_METHODS,
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};

fn verification_method(key: &JWK) -> (String, String) {
    let did = DID_METHODS.generate(key, "key").unwrap().to_string();
    let vm = format!("{did}#{}", did.rsplit(':').next().unwrap());
    (did, vm)
}

/// A UCAN issued by `issuer`'s key but signed with `signer`: when they
/// differ, the signature does not verify.
fn ucan(issuer: &JWK, signer: &JWK, audience: &str, resource: &str, ability: &str) -> String {
    let mut caps = Capabilities::<serde_json::Value>::new();
    caps.with_action(
        resource.parse().unwrap(),
        ability.parse().unwrap(),
        [std::collections::BTreeMap::new()],
    );
    let now = OffsetDateTime::now_utc().unix_timestamp();
    Payload::<serde_json::Value> {
        issuer: verification_method(issuer).1.parse().unwrap(),
        audience: audience.parse().unwrap(),
        not_before: Some(NumericDate::try_from_seconds((now - 60) as f64).unwrap()),
        expiration: NumericDate::try_from_seconds((now + 600) as f64).unwrap(),
        nonce: Some(format!("tc2986-{}", rand::random::<u64>())),
        facts: None,
        proof: vec![],
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, signer)
    .unwrap()
    .encode()
    .unwrap()
}

struct Fixture {
    db: SpaceDatabase<sea_orm::DatabaseConnection, MemoryStore, StaticSecret>,
    owner: JWK,
    holder: String,
    space: SpaceId,
    _directory: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("signatures.sqlite").display()
    );
    let db = SpaceDatabase::new(
        sea_orm::Database::connect(url).await.unwrap(),
        MemoryStore::default(),
        StaticSecret::new(vec![0x42; 32]).unwrap(),
    )
    .await
    .map_err(|error| error.to_string())
    .unwrap();
    let owner = JWK::generate_ed25519().unwrap();
    let (owner_did, _) = verification_method(&owner);
    let (holder, _) = verification_method(&JWK::generate_ed25519().unwrap());
    let space: SpaceId = format!(
        "tinycloud:{}:signatures",
        owner_did.strip_prefix("did:").unwrap()
    )
    .parse()
    .unwrap();
    space::ActiveModel {
        id: Set(SpaceIdWrap(space.clone())),
    }
    .insert(&db.conn)
    .await
    .unwrap();
    Fixture {
        db,
        owner,
        holder,
        space,
        _directory: directory,
    }
}

fn kv_resource(space: &SpaceId) -> String {
    space
        .clone()
        .to_resource(
            "kv".parse().unwrap(),
            Some("docs".parse().unwrap()),
            None,
            None,
        )
        .to_string()
}

#[tokio::test]
async fn a_badly_signed_delegation_is_refused_without_waiting_for_its_space() {
    let fixture = fixture().await;
    let forger = JWK::generate_ed25519().unwrap();
    let token = ucan(
        &fixture.owner,
        &forger,
        &fixture.holder,
        &kv_resource(&fixture.space),
        "tinycloud.kv/get",
    );
    let delegation = Delegation::from_header_ser::<TinyCloudDelegation>(&token).unwrap();

    // Another writer holds the space's write order for the whole check.
    let _held = fixture
        .db
        .acquire_space_sequence_guards(std::slice::from_ref(&fixture.space))
        .await;
    let refused = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture.db.delegate(delegation),
    )
    .await
    .expect("a bad signature is refused before the space's write order");
    assert!(
        matches!(
            refused,
            Err(TxError::InvalidDelegation(
                delegation::DelegationError::InvalidSignature
            ))
        ),
        "{:?}",
        refused.as_ref().map(|_| ()).map_err(ToString::to_string)
    );
}

#[tokio::test]
async fn a_badly_signed_revocation_is_refused_without_waiting_for_its_space() {
    let fixture = fixture().await;
    let granted = ucan(
        &fixture.owner,
        &fixture.owner,
        &fixture.holder,
        &kv_resource(&fixture.space),
        "tinycloud.kv/get",
    );
    fixture
        .db
        .delegate(Delegation::from_header_ser::<TinyCloudDelegation>(&granted).unwrap())
        .await
        .map_err(|error| error.to_string())
        .unwrap();
    let target = crate::hash::hash(granted.as_bytes()).to_cid(0x55);
    let forger = JWK::generate_ed25519().unwrap();
    let (node, _) = verification_method(&JWK::generate_ed25519().unwrap());
    let token = ucan(
        &fixture.owner,
        &forger,
        &node,
        &format!("urn:cid:{target}"),
        "tinycloud.delegation/revoke",
    );
    let revocation = Revocation::from_header_ser::<TinyCloudRevocation>(&token).unwrap();

    let _held = fixture
        .db
        .acquire_space_sequence_guards(std::slice::from_ref(&fixture.space))
        .await;
    let refused = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture.db.revoke(revocation),
    )
    .await
    .expect("a bad signature is refused before the space's write order");
    assert!(
        matches!(
            refused,
            Err(TxError::InvalidRevocation(
                revocation::RevocationError::InvalidSignature
            ))
        ),
        "{:?}",
        refused.as_ref().map(|_| ()).map_err(ToString::to_string)
    );
}

/// Bobbie's #595 review tests (TC-2986 F2-F4), adopted.
mod binding {
    use super::*;
    use tinycloud_auth::ipld_core::cid::Cid;

    type Db = SpaceDatabase<sea_orm::DatabaseConnection, MemoryStore, StaticSecret>;

    fn did_vm(key: &JWK) -> (String, String) {
        let did = DID_METHODS.generate(key, "key").unwrap().to_string();
        let vm = format!("{did}#{}", did.rsplit(':').next().unwrap());
        (did, vm)
    }

    #[allow(clippy::too_many_arguments)]
    fn ucan_full(
        issuer: &JWK,
        signer: &JWK,
        audience: &str,
        resource: &str,
        ability: &str,
        proof: Vec<Cid>,
        nbf: i64,
        exp: i64,
    ) -> String {
        let mut caps = Capabilities::<serde_json::Value>::new();
        caps.with_action(
            resource.parse().unwrap(),
            ability.parse().unwrap(),
            [std::collections::BTreeMap::new()],
        );
        Payload::<serde_json::Value> {
            issuer: did_vm(issuer).1.parse().unwrap(),
            audience: audience.parse().unwrap(),
            not_before: Some(NumericDate::try_from_seconds(nbf as f64).unwrap()),
            expiration: NumericDate::try_from_seconds(exp as f64).unwrap(),
            nonce: Some(format!("tc2986-{}", rand::random::<u64>())),
            facts: None,
            proof,
            attenuation: caps,
        }
        .sign(Algorithm::EdDSA, signer)
        .unwrap()
        .encode()
        .unwrap()
    }

    fn now() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }

    fn ucan(issuer: &JWK, signer: &JWK, audience: &str, resource: &str, ability: &str) -> String {
        ucan_full(
            issuer,
            signer,
            audience,
            resource,
            ability,
            vec![],
            now() - 60,
            now() + 600,
        )
    }

    fn cid_of(token: &str) -> Cid {
        crate::hash::hash(token.as_bytes()).to_cid(0x55)
    }

    fn deleg(token: &str) -> Delegation {
        Delegation::from_header_ser::<TinyCloudDelegation>(token).unwrap()
    }

    fn revoc(token: &str) -> Revocation {
        Revocation::from_header_ser::<TinyCloudRevocation>(token).unwrap()
    }

    struct Fx {
        db: Db,
        owner: JWK,
        holder: JWK,
        space: SpaceId,
        _dir: Option<tempfile::TempDir>,
        _pg: Option<crate::test_support::PostgresTestSchema>,
    }

    async fn on_conn(
        conn: sea_orm::DatabaseConnection,
        dir: Option<tempfile::TempDir>,
        pg: Option<crate::test_support::PostgresTestSchema>,
    ) -> Fx {
        let db = SpaceDatabase::new(
            conn,
            MemoryStore::default(),
            StaticSecret::new(vec![0x42; 32]).unwrap(),
        )
        .await
        .map_err(|error| error.to_string())
        .unwrap();
        let owner = JWK::generate_ed25519().unwrap();
        let (owner_did, _) = did_vm(&owner);
        let space: SpaceId = format!(
            "tinycloud:{}:tc2986",
            owner_did.strip_prefix("did:").unwrap()
        )
        .parse()
        .unwrap();
        space::ActiveModel {
            id: Set(SpaceIdWrap(space.clone())),
        }
        .insert(&db.conn)
        .await
        .unwrap();
        Fx {
            db,
            owner,
            holder: JWK::generate_ed25519().unwrap(),
            space,
            _dir: dir,
            _pg: pg,
        }
    }

    async fn sqlite_fx() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            dir.path().join("r.sqlite").display()
        );
        on_conn(
            sea_orm::Database::connect(url).await.unwrap(),
            Some(dir),
            None,
        )
        .await
    }

    fn kv(space: &SpaceId) -> String {
        space
            .clone()
            .to_resource(
                "kv".parse().unwrap(),
                Some("docs".parse().unwrap()),
                None,
                None,
            )
            .to_string()
    }

    fn short<T>(r: &Result<T, TxError<MemoryStore, StaticSecret>>) -> String {
        match r {
            Ok(_) => "Ok".into(),
            Err(e) => format!("Err({e})"),
        }
    }

    async fn pg_fx(test: &str) -> Option<Fx> {
        let pg = crate::test_support::PostgresTestSchema::new(test).await?;
        let conn = pg.conn.clone();
        Some(on_conn(conn, None, Some(pg)).await)
    }

    async fn hold_pg_space_lock(f: &Fx) -> sea_orm::DatabaseTransaction {
        let other = f._pg.as_ref().unwrap().connect(2).await;
        let tx = begin_write_transaction(&other, None).await.unwrap();
        crate::kv_sync::lock_space_sequences(&tx, [&f.space])
            .await
            .unwrap();
        tx
    }

    /// TC-2986 (F2): `transact` without pre-verification still checks the signature.
    #[tokio::test]
    async fn plain_transact_still_refuses_a_forged_delegation() {
        let f = sqlite_fx().await;
        let forger = JWK::generate_ed25519().unwrap();
        let token = ucan(
            &f.owner,
            &forger,
            &did_vm(&f.holder).0,
            &kv(&f.space),
            "tinycloud.kv/get",
        );
        let r =
            f.db.transact(vec![Event::Delegation(Box::new(deleg(&token)))])
                .await;
        assert!(
            matches!(
                r,
                Err(TxError::InvalidDelegation(
                    delegation::DelegationError::InvalidSignature
                ))
            ),
            "{}",
            short(&r)
        );
    }

    /// TC-2986 (F2): pre-verification is bound to the exact signed bytes: it does not cover a different, forged delegation.
    #[tokio::test]
    async fn a_pre_verified_delegation_does_not_cover_another() {
        let f = sqlite_fx().await;
        let holder = did_vm(&f.holder).0;
        let good = deleg(&ucan(
            &f.owner,
            &f.owner,
            &holder,
            &kv(&f.space),
            "tinycloud.kv/get",
        ));
        let verified =
            PreVerified::delegation::<_, MemoryStore, StaticSecret>(&f.db.conn, &good, None)
                .await
                .map_err(|e| e.to_string())
                .unwrap();
        let forger = JWK::generate_ed25519().unwrap();
        let forged = deleg(&ucan(
            &f.owner,
            &forger,
            &holder,
            &kv(&f.space),
            "tinycloud.kv/put",
        ));
        let r =
            f.db.transact_verified(vec![Event::Delegation(Box::new(forged))], &verified)
                .await;
        assert!(
            matches!(
                r,
                Err(TxError::InvalidDelegation(
                    delegation::DelegationError::InvalidSignature
                ))
            ),
            "{}",
            short(&r)
        );
    }

    /// TC-2986 (F2): the same for revocations.
    #[tokio::test]
    async fn a_pre_verified_revocation_does_not_cover_another() {
        let f = sqlite_fx().await;
        let holder = did_vm(&f.holder).0;
        let g1 = ucan(
            &f.owner,
            &f.owner,
            &holder,
            &kv(&f.space),
            "tinycloud.kv/get",
        );
        let g2 = ucan(
            &f.owner,
            &f.owner,
            &holder,
            &kv(&f.space),
            "tinycloud.kv/put",
        );
        for g in [&g1, &g2] {
            f.db.delegate(deleg(g))
                .await
                .map_err(|e| e.to_string())
                .unwrap();
        }
        let (node, _) = did_vm(&JWK::generate_ed25519().unwrap());
        let good = revoc(&ucan(
            &f.owner,
            &f.owner,
            &node,
            &format!("urn:cid:{}", cid_of(&g1)),
            "tinycloud.delegation/revoke",
        ));
        let verified = PreVerified::revocation::<MemoryStore, StaticSecret>(&good)
            .await
            .map_err(|e| e.to_string())
            .unwrap();
        let forger = JWK::generate_ed25519().unwrap();
        let forged = revoc(&ucan(
            &f.owner,
            &forger,
            &node,
            &format!("urn:cid:{}", cid_of(&g2)),
            "tinycloud.delegation/revoke",
        ));
        let r =
            f.db.transact_verified(vec![Event::Revocation(Box::new(forged))], &verified)
                .await;
        assert!(
            matches!(
                r,
                Err(TxError::InvalidRevocation(
                    revocation::RevocationError::InvalidSignature
                ))
            ),
            "{}",
            short(&r)
        );
    }

    /// TC-2986 (F4): a parent revoked while its child waits for the chain guard refuses the child: that check stays inside the guarded transaction.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_parent_revoked_while_the_child_waits_refuses_the_child() {
        use sea_orm::{ActiveModelTrait, ActiveValue::Set};
        let f = sqlite_fx().await;
        let holder = did_vm(&f.holder).0;
        let third = did_vm(&JWK::generate_ed25519().unwrap()).0;
        let parent_token = ucan(
            &f.owner,
            &f.owner,
            &holder,
            &kv(&f.space),
            "tinycloud.kv/get",
        );
        f.db.delegate(deleg(&parent_token))
            .await
            .map_err(|e| e.to_string())
            .unwrap();
        let parent_cid = cid_of(&parent_token);
        let parent = Hash::from(parent_cid);
        let child = ucan_full(
            &f.holder,
            &f.holder,
            &third,
            &kv(&f.space),
            "tinycloud.kv/get",
            vec![parent_cid],
            now() - 30,
            now() + 300,
        );
        let held =
            f.db.acquire_chain_guards(&[parent])
                .await
                .ok()
                .expect("guard");
        let db = f.db.clone();
        let task = tokio::spawn(async move {
            let r = db.delegate(deleg(&child)).await;
            short(&r)
        });
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(
            !task.is_finished(),
            "child must wait for the parent's chain guard"
        );
        revocation::ActiveModel {
            id: Set(crate::hash::hash(b"tc2986-revocation")),
            revoker: Set(did_vm(&f.owner).0),
            revoked: Set(parent),
            serialization: Set(b"tc2986-revocation".to_vec()),
            revoked_at: Set(Some(OffsetDateTime::now_utc())),
        }
        .insert(&f.db.conn)
        .await
        .unwrap();
        drop(held);
        let out = task.await.unwrap();
        assert!(
            out.starts_with("Err("),
            "child admitted below a revoked parent: {out}"
        );
    }

    /// TC-2986 (F3): a forged delegation citing a victim delegation as parent, and a forged revocation of it, are refused while that chain's guard is held.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn forged_requests_do_not_wait_for_a_victim_chain_guard() {
        let f = sqlite_fx().await;
        let holder = did_vm(&f.holder).0;
        let g = ucan(
            &f.owner,
            &f.owner,
            &holder,
            &kv(&f.space),
            "tinycloud.kv/get",
        );
        f.db.delegate(deleg(&g))
            .await
            .map_err(|e| e.to_string())
            .unwrap();
        let victim = cid_of(&g);
        let held =
            f.db.acquire_chain_guards(&[Hash::from(victim)])
                .await
                .ok()
                .expect("guard");
        let forger = JWK::generate_ed25519().unwrap();
        let child = ucan_full(
            &f.holder,
            &forger,
            &did_vm(&forger).0,
            &kv(&f.space),
            "tinycloud.kv/get",
            vec![victim],
            now() - 30,
            now() + 300,
        );
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            f.db.delegate(deleg(&child)),
        )
        .await
        .expect("forged child must not wait for the victim's chain guard");
        assert!(
            matches!(
                r,
                Err(TxError::InvalidDelegation(
                    delegation::DelegationError::InvalidSignature
                ))
            ),
            "{}",
            short(&r)
        );
        let (node, _) = did_vm(&JWK::generate_ed25519().unwrap());
        let rv = ucan(
            &f.owner,
            &forger,
            &node,
            &format!("urn:cid:{victim}"),
            "tinycloud.delegation/revoke",
        );
        let r = tokio::time::timeout(std::time::Duration::from_secs(5), f.db.revoke(revoc(&rv)))
            .await
            .expect("forged revocation must not wait for the victim's chain guard");
        assert!(
            matches!(
                r,
                Err(TxError::InvalidRevocation(
                    revocation::RevocationError::InvalidSignature
                ))
            ),
            "{}",
            short(&r)
        );
        drop(held);
    }

    /// TC-2986: on PostgreSQL a forged delegation is refused while another session holds the space's advisory lock.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn postgres_a_forged_delegation_is_refused_while_the_database_space_lock_is_held() {
        let Some(f) =
            pg_fx("postgres_a_forged_delegation_is_refused_while_the_database_space_lock_is_held")
                .await
        else {
            return;
        };
        let forger = JWK::generate_ed25519().unwrap();
        let token = ucan(
            &f.owner,
            &forger,
            &did_vm(&f.holder).0,
            &kv(&f.space),
            "tinycloud.kv/get",
        );
        let lock = hold_pg_space_lock(&f).await;
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            f.db.delegate(deleg(&token)),
        )
        .await
        .expect("forged delegation must not wait for the DB space lock");
        assert!(
            matches!(
                r,
                Err(TxError::InvalidDelegation(
                    delegation::DelegationError::InvalidSignature
                ))
            ),
            "{}",
            short(&r)
        );
        lock.rollback().await.unwrap();
    }

    /// TC-2986: the same for a forged revocation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn postgres_a_forged_revocation_is_refused_while_the_database_space_lock_is_held() {
        let Some(f) =
            pg_fx("postgres_a_forged_revocation_is_refused_while_the_database_space_lock_is_held")
                .await
        else {
            return;
        };
        let g = ucan(
            &f.owner,
            &f.owner,
            &did_vm(&f.holder).0,
            &kv(&f.space),
            "tinycloud.kv/get",
        );
        f.db.delegate(deleg(&g))
            .await
            .map_err(|e| e.to_string())
            .unwrap();
        let forger = JWK::generate_ed25519().unwrap();
        let (node, _) = did_vm(&JWK::generate_ed25519().unwrap());
        let token = ucan(
            &f.owner,
            &forger,
            &node,
            &format!("urn:cid:{}", cid_of(&g)),
            "tinycloud.delegation/revoke",
        );
        let lock = hold_pg_space_lock(&f).await;
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            f.db.revoke(revoc(&token)),
        )
        .await
        .expect("forged revocation must not wait for the DB space lock");
        assert!(
            matches!(
                r,
                Err(TxError::InvalidRevocation(
                    revocation::RevocationError::InvalidSignature
                ))
            ),
            "{}",
            short(&r)
        );
        lock.rollback().await.unwrap();
    }
}
