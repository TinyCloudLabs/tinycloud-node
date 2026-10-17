//! Two live recovery chains can cross at principal locks during key revocation.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;
use std::{collections::BTreeMap, time::Duration};
use time::OffsetDateTime;
use tinycloud_auth::{
    authorization::{Cid, HeaderEncode, TinyCloudDelegation},
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    hash::{hash, Hash},
    key_authority,
    keys::{public_key_to_did_key, Keypair, StaticSecret},
    migrations::Migrator,
    models::{
        abilities, actor, delegation, delegation_cid_alias,
        key_revocation::{self, KeyRevokeError, KeyRevokeScope, VerifiedKeyRevoke},
    },
    recovery_authority,
    relationships::parent_delegations,
    sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectOptions, ConnectionTrait, Database,
        DatabaseConnection, DatabaseTransaction, DbBackend, EntityTrait, Statement,
        TransactionTrait,
    },
    sea_orm_migration::MigratorTrait,
    storage::MemoryStore,
    util::DelegationInfo,
    SpaceDatabase,
};

fn signer(seed: u8) -> (JWK, String, String) {
    let key = Keypair::ed25519_from_bytes([seed; 32]).unwrap();
    let public = key.clone().try_into_ed25519().unwrap().public().to_bytes();
    let did = public_key_to_did_key(key.public());
    let jwk = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA",
        "x": URL_SAFE_NO_PAD.encode(public),
        "d": URL_SAFE_NO_PAD.encode([seed; 32]),
    }))
    .unwrap();
    let fragment = format!("{did}#{}", did.trim_start_matches("did:key:"));
    (jwk, did, fragment)
}

fn signed_grant(
    seed: u8,
    audience: &str,
    target: &str,
    parent: Option<&str>,
    nonce: &str,
    now: i64,
) -> String {
    let (jwk, _, issuer) = signer(seed);
    let mut caps = Capabilities::<serde_json::Value>::new();
    let caveat: BTreeMap<String, serde_json::Value> = serde_json::from_value(json!({
        "version": 1, "targetDid": target, "scope": {"kind": "global"}
    }))
    .unwrap();
    caps.with_action(
        format!("urn:tinycloud:key:{target}").parse().unwrap(),
        "tinycloud.key/revoke".parse().unwrap(),
        [caveat],
    );
    Payload::<serde_json::Value> {
        issuer: issuer.parse().unwrap(),
        audience: audience.parse().unwrap(),
        not_before: Some(NumericDate::try_from_seconds((now - 60) as f64).unwrap()),
        expiration: NumericDate::try_from_seconds((now + 600) as f64).unwrap(),
        nonce: Some(nonce.to_owned()),
        facts: None,
        proof: parent
            .into_iter()
            .map(|cid| cid.parse::<Cid>().unwrap())
            .collect(),
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, &jwk)
    .unwrap()
    .encode()
    .unwrap()
}

async fn persist_grant(db: &DatabaseConnection, serialized: &str) -> String {
    let (_, bytes) = TinyCloudDelegation::decode(serialized).unwrap();
    let info = DelegationInfo::try_from(TinyCloudDelegation::from_bytes(&bytes).unwrap()).unwrap();
    assert_eq!(info.capabilities.len(), 1);
    let id = hash(&bytes);
    let cid = id.to_cid(0x55).to_string();
    assert_eq!(bytes, serialized.as_bytes());
    for did in [&info.delegator, &info.delegate] {
        if actor::Entity::find_by_id(did.to_owned())
            .one(db)
            .await
            .unwrap()
            .is_none()
        {
            actor::ActiveModel {
                id: Set(did.to_owned()),
            }
            .insert(db)
            .await
            .unwrap();
        }
    }
    delegation::ActiveModel {
        id: Set(id),
        delegator: Set(info.delegator),
        delegatee: Set(info.delegate),
        expiry: Set(info.expiry),
        issued_at: Set(info.issued_at),
        not_before: Set(info.not_before),
        facts: Set(None),
        serialization: Set(bytes.clone()),
    }
    .insert(db)
    .await
    .unwrap();
    let cap = &info.capabilities[0];
    abilities::ActiveModel {
        resource: Set(cap.resource.clone()),
        ability: Set(cap.ability.clone()),
        delegation: Set(id),
        caveats: Set(cap.caveats.clone()),
    }
    .insert(db)
    .await
    .unwrap();
    delegation_cid_alias::ActiveModel {
        id: Set(id),
        canonical: Set(hash(&bytes)),
        encrypted: Set(false),
    }
    .insert(db)
    .await
    .unwrap();
    for parent in &info.parents {
        parent_delegations::ActiveModel {
            parent: Set(Hash::from(*parent)),
            child: Set(id),
        }
        .insert(db)
        .await
        .unwrap();
    }
    cid
}

fn request(target: &str, issuer: &str, proof: String, nonce: &str, now: i64) -> VerifiedKeyRevoke {
    let mut authorization_hash = [0; 32];
    authorization_hash.copy_from_slice(hash(nonce.as_bytes()).as_ref());
    VerifiedKeyRevoke {
        target_did: target.to_owned(),
        issuer_did: issuer.to_owned(),
        scope: KeyRevokeScope::Global,
        nonce: nonce.to_owned(),
        authorization_hash,
        proof_cids: vec![proof],
        not_before: now,
        valid_after: None,
        expires_at: now + 60,
    }
}

// The names consist only of our numeric PID and timestamp, never URL/user input.
struct Schema {
    url: String,
    name: String,
}

impl Drop for Schema {
    fn drop(&mut self) {
        let (url, name) = (self.url.clone(), self.name.clone());
        let result = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let conn = Database::connect(ConnectOptions::new(url)).await.unwrap();
                    conn.execute_unprepared(&format!("DROP SCHEMA IF EXISTS {name} CASCADE"))
                        .await
                        .unwrap();
                })
        })
        .join();
        assert!(result.is_ok(), "drop isolated PostgreSQL schema");
    }
}

async fn wait_for_target_updates(
    admin: &DatabaseConnection,
    names: &[&str],
    holder: Option<i32>,
) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    let blocker_clause = holder.map_or_else(
        || "cardinality(pg_blocking_pids(pid)) > 0".to_owned(),
        |pid| format!("{pid} = ANY(pg_blocking_pids(pid))"),
    );
    loop {
        // A first waiter is pinned to our holder. A later waiter can be
        // queued behind that earlier waiter rather than behind the holder.
        let rows = admin
            .query_all(Statement::from_string(
                DbBackend::Postgres,
                format!(
                    "SELECT application_name FROM pg_stat_activity \
             WHERE application_name IN ('{}') AND state = 'active' \
             AND wait_event_type = 'Lock' AND {blocker_clause} \
             AND query LIKE '%key_revocation_target%' AND query LIKE '%FOR UPDATE%'",
                    names.join("','"),
                ),
            ))
            .await
            .expect("inspect isolated PostgreSQL wait events");
        if rows.len() == names.len() {
            let seen: Vec<String> = rows
                .iter()
                .map(|row| row.try_get("", "application_name").unwrap())
                .collect();
            if names
                .iter()
                .all(|name| seen.iter().any(|seen| seen == name))
            {
                return true;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_crossed_recovery_revokes_do_not_deadlock() {
    let url = match std::env::var("TINYCLOUD_TEST_POSTGRES_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            assert!(std::env::var_os("CI").is_none(),
                "postgres_crossed_recovery_revokes_do_not_deadlock requires TINYCLOUD_TEST_POSTGRES_URL in CI");
            eprintln!("skipping PostgreSQL-only recovery order test: TINYCLOUD_TEST_POSTGRES_URL is unset");
            return;
        }
    };
    let schema = Schema {
        url: url.clone(),
        name: format!(
            "tc1149_{}_{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ),
    };
    let mut admin_options = ConnectOptions::new(url.clone());
    admin_options.max_connections(2).sqlx_logging(false);
    let admin = Database::connect(admin_options)
        .await
        .expect("connect PostgreSQL observer");
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {}", schema.name))
        .await
        .unwrap();
    let connect = |label: &str| {
        let app = format!("{}_{}", schema.name, label);
        let mut options = ConnectOptions::new(format!(
            "{}{}application_name={app}",
            url,
            if url.contains('?') { "&" } else { "?" }
        ));
        options
            .max_connections(1)
            .sqlx_logging(false)
            .set_schema_search_path(schema.name.clone());
        (app, options)
    };
    let (first_name, first_options) = connect("first");
    let (second_name, second_options) = connect("second");
    let first_conn = Database::connect(first_options).await.unwrap();
    Migrator::up(&first_conn, None).await.unwrap();
    let second_conn = Database::connect(second_options).await.unwrap();
    let first = SpaceDatabase::new(
        first_conn.clone(),
        MemoryStore::default(),
        StaticSecret::new(vec![0; 32]).unwrap(),
    )
    .await
    .unwrap();
    let second = SpaceDatabase::new(
        second_conn,
        MemoryStore::default(),
        StaticSecret::new(vec![0; 32]).unwrap(),
    )
    .await
    .unwrap();

    // R and S sort before either target. Both transactions reach the held
    // issuer rows: the unfixed path already holds SHARE on the opposite
    // intermediate, whereas the fixed path blocks before taking that SHARE.
    let mut identities: Vec<(u8, String)> = (1..=8).map(|seed| (seed, signer(seed).1)).collect();
    identities.sort_by(|left, right| left.1.cmp(&right.1));
    let (_, r) = &identities[0];
    let (_, s) = &identities[1];
    let (a_seed, a) = &identities[2];
    let (b_seed, b) = &identities[3];
    assert!(r < a && s < b && a != b);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let a_root = persist_grant(
        &first_conn,
        &signed_grant(*a_seed, b, a, None, "a-root", now),
    )
    .await;
    let a_tip = persist_grant(
        &first_conn,
        &signed_grant(*b_seed, r, a, Some(&a_root), "a-tip", now),
    )
    .await;
    let b_root = persist_grant(
        &first_conn,
        &signed_grant(*b_seed, a, b, None, "b-root", now),
    )
    .await;
    let b_tip = persist_grant(
        &first_conn,
        &signed_grant(*a_seed, s, b, Some(&b_root), "b-tip", now),
    )
    .await;
    let a_request = request(a, r, a_tip, "revoke-a", now);
    let b_request = request(b, s, b_tip, "revoke-b", now);

    // Demonstrate both independently valid, signed recovery paths before
    // arranging any waits. A Forbidden caused by fixture drift is not a red.
    for req in [&a_request, &b_request] {
        let tx = first_conn.begin().await.unwrap();
        let mut expiry = None;
        assert!(
            recovery_authority::is_authorized(
                &tx,
                req,
                OffsetDateTime::now_utc(),
                None,
                &mut expiry
            )
            .await
            .unwrap(),
            "signed recovery grant must be valid before the lock schedule"
        );
        assert!(expiry.is_some());
        tx.rollback().await.unwrap();
    }
    for did in [a, b, r, s] {
        key_revocation::target::ActiveModel {
            target_did: Set(did.clone()),
        }
        .insert(&first_conn)
        .await
        .unwrap();
    }
    let holder: DatabaseTransaction = admin.begin().await.unwrap();
    let held = holder
        .query_one(Statement::from_string(
            DbBackend::Postgres,
            format!(
                "SELECT count(*) AS n FROM \
         (SELECT target_did FROM {}.key_revocation_target \
          WHERE target_did IN ('{r}', '{s}') ORDER BY target_did FOR UPDATE) AS held",
                schema.name,
            ),
        ))
        .await
        .unwrap()
        .unwrap();
    let held_count: i64 = held.try_get("", "n").unwrap();
    assert_eq!(held_count, 2, "test transaction must lock both issuers");
    let pid = holder
        .query_one(Statement::from_string(
            DbBackend::Postgres,
            "SELECT pg_backend_pid() AS pid".to_owned(),
        ))
        .await
        .unwrap()
        .unwrap();
    let holder_pid: i32 = pid.try_get("", "pid").unwrap();
    let first_job = tokio::spawn(async move { first.revoke_key(a_request).await });
    let second_job = tokio::spawn(async move { second.revoke_key(b_request).await });
    let reached =
        wait_for_target_updates(&admin, &[&first_name, &second_name], Some(holder_pid)).await;
    holder.rollback().await.expect("release issuer row locks");
    if !reached {
        first_job.abort();
        second_job.abort();
        panic!("both recovery revokes must reach their ordered exclusive target/issuer row locks");
    }
    let mut committed = 0;
    for job in [first_job, second_job] {
        let result = tokio::time::timeout(Duration::from_secs(12), job)
            .await
            .expect("recovery revoke must finish without a PostgreSQL lock cycle")
            .expect("revoke task must not panic");
        assert!(
            matches!(&result, Ok(_) | Err(KeyRevokeError::Forbidden)),
            "concurrent recovery revoke returned a database/deadlock error: {result:?}"
        );
        if result.is_ok() {
            committed += 1;
        }
    }
    assert!(
        committed >= 1,
        "at least one live recovery revoke must commit"
    );
    first_conn.close().await.unwrap();
    admin.close().await.unwrap();
}

/// Recovery's Rust byte order must agree with the direct/admission transaction
/// even when PostgreSQL's configured text collation orders those DIDs differently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_mixed_direct_and_recovery_locks_share_byte_order() {
    let url = match std::env::var("TINYCLOUD_TEST_POSTGRES_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            assert!(
                std::env::var_os("CI").is_none(),
                "mixed lock-order regression requires TINYCLOUD_TEST_POSTGRES_URL in CI"
            );
            eprintln!("skipping PostgreSQL-only mixed lock-order test: URL is unset");
            return;
        }
    };
    let schema = Schema {
        url: url.clone(),
        name: format!(
            "tc1149_mixed_{}_{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ),
    };
    let mut admin_options = ConnectOptions::new(url.clone());
    admin_options.max_connections(2).sqlx_logging(false);
    let admin = Database::connect(admin_options).await.unwrap();
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {}", schema.name))
        .await
        .unwrap();
    let connect = |label: &str| {
        let app = format!("{}_{}", schema.name, label);
        let mut options = ConnectOptions::new(format!(
            "{}{}application_name={app}",
            url,
            if url.contains('?') { "&" } else { "?" }
        ));
        options
            .max_connections(1)
            .sqlx_logging(false)
            .set_schema_search_path(schema.name.clone());
        (app, options)
    };
    let (recovery_name, recovery_options) = connect("recovery");
    let (direct_name, direct_options) = connect("direct");
    let recovery_conn = Database::connect(recovery_options).await.unwrap();
    Migrator::up(&recovery_conn, None).await.unwrap();
    recovery_conn
        .execute_unprepared(
            "ALTER TABLE key_revocation_target ALTER COLUMN target_did TYPE varchar(255) COLLATE \"en-US-x-icu\"",
        )
        .await
        .expect("PostgreSQL must support the test's non-bytewise ICU collation");
    let direct_conn = Database::connect(direct_options).await.unwrap();
    let recovery = SpaceDatabase::new(
        recovery_conn.clone(),
        MemoryStore::default(),
        StaticSecret::new(vec![0; 32]).unwrap(),
    )
    .await
    .unwrap();

    let mut identities: Vec<(u8, String)> = (1..=64).map(|seed| (seed, signer(seed).1)).collect();
    identities.sort_by(|left, right| left.1.cmp(&right.1));
    for (_, did) in &identities {
        key_revocation::target::ActiveModel {
            target_did: Set(did.clone()),
        }
        .insert(&recovery_conn)
        .await
        .unwrap();
    }
    let db_order = recovery_conn
        .query_all(Statement::from_string(
            DbBackend::Postgres,
            "SELECT target_did FROM key_revocation_target ORDER BY target_did".to_owned(),
        ))
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.try_get::<String>("", "target_did").unwrap())
        .collect::<Vec<_>>();
    let mut chosen = None;
    for first in 1..identities.len() {
        for second in first + 1..identities.len() {
            let a = &identities[first].1;
            let b = &identities[second].1;
            if db_order.iter().position(|did| did == b).unwrap()
                < db_order.iter().position(|did| did == a).unwrap()
            {
                chosen = Some((identities[first].clone(), identities[second].clone()));
                break;
            }
        }
        if chosen.is_some() {
            break;
        }
    }
    let ((a_seed, a), (b_seed, b)) =
        chosen.expect("fixture must assert an actual database-versus-Rust DID ordering inversion");
    let r = identities[0].1.clone();
    assert!(r < a && a < b);
    assert!(
        db_order.iter().position(|did| did == &b).unwrap()
            < db_order.iter().position(|did| did == &a).unwrap(),
        "PostgreSQL sorts B before A while canonical Rust bytes sort A before B"
    );
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let root = persist_grant(
        &recovery_conn,
        &signed_grant(a_seed, &b, &a, None, "mixed-root", now),
    )
    .await;
    let tip = persist_grant(
        &recovery_conn,
        &signed_grant(b_seed, &r, &a, Some(&root), "mixed-tip", now),
    )
    .await;
    let recovery_request = request(&a, &r, tip, "mixed-recovery", now);
    let proof_tx = recovery_conn.begin().await.unwrap();
    let mut expiry = None;
    assert!(
        recovery_authority::is_authorized(
            &proof_tx,
            &recovery_request,
            OffsetDateTime::now_utc(),
            None,
            &mut expiry
        )
        .await
        .unwrap(),
        "signed recovery chain is valid before arranging either lock wait"
    );
    proof_tx.rollback().await.unwrap();

    let holder = admin.begin().await.unwrap();
    holder
        .query_one(Statement::from_string(
            DbBackend::Postgres,
            format!(
                "SELECT target_did FROM {}.key_revocation_target WHERE target_did = '{}' FOR UPDATE",
                schema.name, a
            ),
        ))
        .await
        .unwrap()
        .expect("holder locks A");
    let holder_pid: i32 = holder
        .query_one(Statement::from_string(
            DbBackend::Postgres,
            "SELECT pg_backend_pid() AS pid".to_owned(),
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "pid")
        .unwrap();
    let recovered = tokio::spawn(async move { recovery.revoke_key(recovery_request).await });
    assert!(
        wait_for_target_updates(&admin, &[&recovery_name], Some(holder_pid)).await,
        "the recovery path must be blocked at A before direct locks are requested"
    );
    let direct = tokio::spawn(async move {
        let tx = direct_conn.begin().await.unwrap();
        let result = key_authority::lock_targets(&tx, &[a, b], true).await;
        tx.rollback().await.unwrap();
        result
    });
    let reached = wait_for_target_updates(&admin, &[&recovery_name, &direct_name], None).await;
    let diagnostic = if reached {
        Vec::new()
    } else {
        admin
            .query_all(Statement::from_string(
                DbBackend::Postgres,
                format!(
                    "SELECT application_name, state, COALESCE(wait_event_type, '') AS wait, \
                     cardinality(pg_blocking_pids(pid)) AS blockers, \
                     query LIKE '%key_revocation_target%' AS target_sql, \
                     query LIKE '%FOR UPDATE%' AS update_sql \
                     FROM pg_stat_activity WHERE application_name IN ('{recovery_name}', '{direct_name}')"
                ),
            ))
            .await
            .unwrap()
            .into_iter()
            .map(|row| {
                let app: String = row.try_get("", "application_name").unwrap();
                (
                    if app == recovery_name { "recovery" } else { "direct" },
                    row.try_get::<String>("", "state").unwrap(),
                    row.try_get::<String>("", "wait").unwrap(),
                    row.try_get::<i32>("", "blockers").unwrap(),
                    row.try_get::<bool>("", "target_sql").unwrap(),
                    row.try_get::<bool>("", "update_sql").unwrap(),
                )
            })
            .collect::<Vec<_>>()
    };
    holder
        .rollback()
        .await
        .expect("release A after both paths are waiting");
    assert!(
        reached,
        "both real lock paths must block at held A; count-only connection states: {diagnostic:?}"
    );
    let recovered = tokio::time::timeout(Duration::from_secs(12), recovered)
        .await
        .expect("recovery path must not deadlock")
        .expect("recovery task must not panic");
    let direct = tokio::time::timeout(Duration::from_secs(12), direct)
        .await
        .expect("direct path must not deadlock")
        .expect("direct task must not panic");
    assert!(recovered.is_ok(), "valid recovery failed: {recovered:?}");
    assert!(direct.is_ok(), "direct/admission lock failed: {direct:?}");
    recovery_conn.close().await.unwrap();
    admin.close().await.unwrap();
}
