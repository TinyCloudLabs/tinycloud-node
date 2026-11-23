//! TC-4092: after the owner revokes a delegation and a lease and the
//! records of their space are purged, is the same signed chain admitted again
//! through the real admission path (`SpaceDatabase::delegate`, what `POST
//! /delegate` calls) and does the old lease stamp again?
use super::*;
use crate::storage::memory::MemoryStore;
use std::collections::BTreeMap;
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

pub(super) fn key(seed: u8) -> (JWK, String, String) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let secret = [seed; 32];
    let signing = ed25519_dalek::SigningKey::from_bytes(&secret);
    let jwk: JWK = serde_json::from_value(serde_json::json!({
        "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA",
        "x": URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),
        "d": URL_SAFE_NO_PAD.encode(secret),
    }))
    .unwrap();
    let did = DID_METHODS.generate(&jwk, "key").unwrap().to_string();
    let method = format!("{did}#{}", did.rsplit(':').next().unwrap());
    (jwk, did, method)
}

pub(super) fn token(
    issuer_seed: u8,
    audience: &str,
    resource: &str,
    ability: &str,
    parents: &[Hash],
    nonce: &str,
    exp: i64,
) -> String {
    let (jwk, _, method) = key(issuer_seed);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut caps = Capabilities::<serde_json::Value>::new();
    caps.with_action(
        resource.parse().unwrap(),
        ability.parse().unwrap(),
        [BTreeMap::new()],
    );
    Payload::<serde_json::Value> {
        issuer: method.parse().unwrap(),
        audience: audience.parse().unwrap(),
        not_before: Some(NumericDate::try_from_seconds((now - 5) as f64).unwrap()),
        expiration: NumericDate::try_from_seconds(exp as f64).unwrap(),
        nonce: Some(nonce.to_owned()),
        facts: None,
        proof: parents.iter().map(|id| id.to_cid(0x55)).collect(),
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, &jwk)
    .unwrap()
    .encode()
    .unwrap()
}

pub(super) fn deleg(token: &str) -> Delegation {
    Delegation::from_header_ser::<TinyCloudDelegation>(token).unwrap()
}

pub(super) fn cid_of(token: &str) -> Hash {
    crate::hash::hash(token.as_bytes())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// (a) records gone, the space row still hosted; fence attached, nothing fenced.
    Hosted,
    /// (b) records gone, the space row gone too; fence attached, nothing fenced;
    /// the owner posts a host delegation again first.
    Rehosted,
    /// (c) records gone, space row gone, permanent purge fence on the space.
    Fenced,
    /// Originals and leases that name NO space (an encryption-network
    /// resource): records gone, the owner and the space fenced.
    NonSpace,
}

async fn count(db: &sea_orm::DatabaseConnection, table: &str) -> i64 {
    db.query_one(Statement::from_string(
        db.get_database_backend(),
        format!("SELECT COUNT(*) AS n FROM {table}"),
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get::<i64>("", "n")
    .unwrap()
}

fn outcome<T>(result: &Result<T, TxError<MemoryStore, StaticSecret>>) -> String {
    match result {
        Ok(_) => "ADMITTED".to_owned(),
        Err(error) => format!("REFUSED: {error}"),
    }
}

async fn scenario(state: State, conn: sea_orm::DatabaseConnection) -> Vec<String> {
    let mut report = Vec::new();
    let secret = StaticSecret::new(vec![0x42; 32]).unwrap();
    let mut db = SpaceDatabase::new(conn, MemoryStore::default(), secret.clone())
        .await
        .map_err(|error| error.to_string())
        .unwrap();
    let identity = db.renewal_identity().unwrap().clone();
    let (_, owner_did, _) = key(0x11);
    let (_, holder1, _) = key(0x21);
    let (_, holder2, _) = key(0x22);
    let (_, holder3, _) = key(0x23);
    let space: SpaceId = format!(
        "tinycloud:{}:default",
        owner_did.strip_prefix("did:").unwrap()
    )
    .parse()
    .unwrap();
    let (kv, ability) = if state == State::NonSpace {
        (
            format!("urn:tinycloud:encryption:{owner_did}:default"),
            "tinycloud.encryption/decrypt",
        )
    } else {
        (
            space
                .clone()
                .to_resource(
                    "kv".parse().unwrap(),
                    Some("docs".parse().unwrap()),
                    None,
                    None,
                )
                .to_string(),
            "tinycloud.kv/get",
        )
    };
    let host = space
        .clone()
        .to_resource("space".parse().unwrap(), None, None, None)
        .to_string();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let host_token = |nonce: &str| {
        token(
            0x11,
            &owner_did,
            &host,
            "tinycloud.space/host",
            &[],
            nonce,
            now + 3600,
        )
    };
    // The space is hosted by the owner's host delegation, as in production.
    db.delegate(deleg(&host_token("host-1")))
        .await
        .map_err(|error| error.to_string())
        .unwrap();
    assert_eq!(count(&db.conn, "space").await, 1);

    // Plain chain: root -> child, signed by the owner then by holder 1.
    let root = token(0x11, &holder1, &kv, ability, &[], "root", now + 3600);
    let child = token(
        0x21,
        &holder2,
        &kv,
        ability,
        &[cid_of(&root)],
        "child",
        now + 3000,
    );
    // Lease chain: original (holder 3) and its owner-signed lease.
    let original = token(0x11, &holder3, &kv, ability, &[], "original", now + 3600);
    let original_cid = cid_of(&original).to_cid(0x55).to_string();
    let lease = token(
        0x11,
        &identity.renewer_did,
        &format!("urn:cid:{original_cid}"),
        "tinycloud.delegation/renew",
        &[],
        "lease",
        now + 7200,
    );
    for t in [&root, &child, &original, &lease] {
        db.delegate(deleg(t))
            .await
            .map_err(|error| error.to_string())
            .unwrap();
    }
    assert_eq!(count(&db.conn, "renewal_lease").await, 1);

    // Control: the live lease stamps.
    let request = |label: &str| {
        let invocation =
            tinycloud_auth::authorization::TinyCloudInvocation::decode(&original).unwrap();
        let mut request = crate::renewal::StampIssue {
            invocation: crate::util::InvocationInfo::try_from(invocation).unwrap(),
            original_cid: original_cid.clone(),
            lease_cid: cid_of(&lease).to_cid(0x55).to_string(),
            replay_hash: crate::hash::hash(label.as_bytes()),
            replay_expires_at: now + 600,
        };
        request.invocation.invoker = identity.renewer_did.clone();
        request.invocation.parents = vec![request.lease_cid.parse().unwrap()];
        request.invocation.capabilities = vec![crate::util::Capability {
            resource: format!("urn:cid:{original_cid}").parse().unwrap(),
            ability: "tinycloud.delegation/renew".to_owned().try_into().unwrap(),
            caveats: Default::default(),
        }];
        request
    };
    db.issue_renewal_stamp(request("control"))
        .await
        .expect("control: the live lease stamps");
    report.push(format!(
        "control: renewal_stamp={}, renewal_lease={:?}",
        count(&db.conn, "renewal_stamp").await,
        lease_states(&db.conn).await
    ));

    // The owner revokes the child and the lease through /revoke.
    for target in [&child, &lease] {
        let revocation = token(
            0x11,
            &owner_did,
            &format!("urn:cid:{}", cid_of(target).to_cid(0x55)),
            "tinycloud.delegation/revoke",
            &[],
            &format!("revoke-{}", &target[target.len() - 8..]),
            now + 600,
        );
        db.revoke(Revocation::from_header_ser::<TinyCloudRevocation>(&revocation).unwrap())
            .await
            .map_err(|error| error.to_string())
            .unwrap();
    }
    assert_eq!(count(&db.conn, "revocation").await, 2);
    // Before any purge: the revoked lease's identical bytes re-posted. The
    // existing-row branch of register_lease_checked must not answer Ok.
    let before = db.delegate(deleg(&lease)).await;
    report.push(format!(
        "pre-purge re-post lease (revoked): {}",
        outcome(&before)
    ));
    if before.is_ok() {
        report.push("VIOLATION: revoked lease re-post is Ok before any purge".to_owned());
    }

    let keys = std::sync::Arc::new(
        crate::space_purge_ledger::LedgerKeys::new(
            "test".into(),
            BTreeMap::from([("test".into(), vec![7; 32])]),
        )
        .unwrap(),
    );
    let fence = std::sync::Arc::new(crate::space_purge_fence::SpacePurgeFence::new(keys.clone()));
    fence.set_serving_ready(true);
    if state == State::Fenced {
        // Fence time, as in the purge accept transaction: the space fence and
        // the terminal mark of its leases in ONE transaction, before any
        // record is deleted.
        assert_eq!(lease_states(&db.conn).await, ["active"]);
        let tx = db.conn.begin().await.unwrap();
        fence
            .fence_hmac(
                &tx,
                "space",
                "test",
                &keys
                    .target_hmac("test", "space", &space.to_string())
                    .unwrap(),
            )
            .await
            .unwrap();
        let stopped = crate::space_purge_records::terminate_space_leases(&tx, &space.to_string())
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let states = lease_states(&db.conn).await;
        report.push(format!(
            "fence time: {stopped} lease row(s) terminal, renewal_lease={states:?}, renewal_stamp={}",
            count(&db.conn, "renewal_stamp").await
        ));
        if stopped != 1 || states != ["revoked"] {
            report.push("VIOLATION: the lease is not terminal at fence time".to_owned());
        }
    }

    // Purge the records of the space.
    let mut deleted: std::collections::HashSet<Hash> = [&root, &child, &original, &lease]
        .iter()
        .map(|t| cid_of(t))
        .collect();
    deleted.insert(cid_of(&host_token("host-1")));
    for row in db
        .conn
        .query_all(Statement::from_string(
            db.conn.get_database_backend(),
            "SELECT id FROM revocation".to_owned(),
        ))
        .await
        .unwrap()
    {
        deleted.insert(row.try_get::<Hash>("", "id").unwrap());
    }
    let tx = db.conn.begin().await.unwrap();
    crate::space_purge_records::remove_records_for_test(&tx, &deleted)
        .await
        .unwrap();
    if state != State::Hosted {
        // The space-keyed rows complete_space deletes before the space row.
        for table in ["event_order", "epoch_order", "epoch_head", "epoch", "space"] {
            tx.execute(Statement::from_string(
                db.conn.get_database_backend(),
                format!("DELETE FROM {table}"),
            ))
            .await
            .unwrap();
        }
    }
    tx.commit().await.unwrap();
    // The node's purge fence is attached for every state, as in production;
    // only (c) and the non-space case write fence rows.
    let fenced_kinds: &[(&str, String)] = match state {
        State::Hosted | State::Rehosted => &[],
        State::Fenced => &[("space", space.to_string())],
        // The owner was erased after the space purge: owner and space fenced.
        State::NonSpace => &[
            ("space", space.to_string()),
            ("owner", space.did().as_str().to_owned()),
        ],
    };
    for (kind, target) in fenced_kinds {
        let tx = db.conn.begin().await.unwrap();
        fence
            .fence_hmac(
                &tx,
                kind,
                "test",
                &keys.target_hmac("test", kind, target).unwrap(),
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    db = db.with_space_purge_fence(fence);
    report.push(format!(
        "after purge: delegation={}, revocation={}, renewal_lease={:?}, renewal_stamp={}, space={}",
        count(&db.conn, "delegation").await,
        count(&db.conn, "revocation").await,
        lease_states(&db.conn).await,
        count(&db.conn, "renewal_stamp").await,
        count(&db.conn, "space").await,
    ));
    if lease_states(&db.conn)
        .await
        .iter()
        .any(|state| state == "active")
    {
        report.push("VIOLATION: a lease row is 'active' after its records were purged".to_owned());
    }
    // TC-4092 (lead, 17:47Z): in EVERY state, the fenced one included, the
    // purge deletes the lease row and its stamp history; none is left behind
    // to be 'active' or 'terminal'.
    if !lease_states(&db.conn).await.is_empty() || count(&db.conn, "renewal_stamp").await != 0 {
        report.push(
            "VIOLATION: a renewal_lease or renewal_stamp row survives the purge of its records"
                .to_owned(),
        );
    }

    if state != State::Hosted {
        let rehost = db.delegate(deleg(&host_token("host-2"))).await;
        report.push(format!(
            "re-host (fresh host delegation): {}",
            outcome(&rehost)
        ));
        // The same host delegation, byte for byte.
        let same = db.delegate(deleg(&host_token("host-1"))).await;
        report.push(format!(
            "re-host (identical host delegation): {}",
            outcome(&same)
        ));
    }
    for (label, t, revoked) in [
        ("root", &root, false),
        ("child (revoked)", &child, true),
        ("original", &original, false),
        ("lease (revoked)", &lease, true),
    ] {
        let result = db.delegate(deleg(t)).await;
        report.push(format!("re-post {label}: {}", outcome(&result)));
        if revoked && result.is_ok() {
            report.push(format!("VIOLATION: revoked {label} admitted again"));
        }
    }
    let child_row = count_where(&db.conn, "delegation", &cid_of(&child)).await;
    let child_revoked = crate::models::revocation::is_revoked(&db.conn, &cid_of(&child))
        .await
        .unwrap();
    report.push(format!(
        "child stored={child_row}, still revoked={child_revoked}; renewal_lease={:?}, renewal_stamp={}",
        lease_states(&db.conn).await,
        count(&db.conn, "renewal_stamp").await,
    ));
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let stamp = db.issue_renewal_stamp(request("after purge")).await;
    report.push(format!(
        "stamp for the old lease: {}",
        match &stamp {
            Ok(record) => format!("ISSUED new_end={}", record.new_end),
            Err(error) => format!("REFUSED: {error:?}"),
        }
    ));
    if stamp.is_ok() {
        report.push("VIOLATION: a purged, revoked lease stamped".to_owned());
    }
    report
}

async fn lease_states(db: &sea_orm::DatabaseConnection) -> Vec<String> {
    db.query_all(Statement::from_string(
        db.get_database_backend(),
        "SELECT state FROM renewal_lease".to_owned(),
    ))
    .await
    .unwrap()
    .iter()
    .map(|row| row.try_get::<String>("", "state").unwrap())
    .collect()
}

async fn count_where(db: &sea_orm::DatabaseConnection, table: &str, id: &Hash) -> i64 {
    db.query_one(Statement::from_sql_and_values(
        db.get_database_backend(),
        format!("SELECT COUNT(*) AS n FROM {table} WHERE id = $1"),
        [Vec::<u8>::from(*id).into()],
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get::<i64>("", "n")
    .unwrap()
}

/// The safe outcome in every state: the revoked child and the revoked lease
/// are not admitted again, the old lease never stamps, and no lease or stamp
/// row stays once its records are purged. Each state has its own test, on
/// SQLite and on PostgreSQL. Failed on main in all four states (a re-admitted
/// revocation in `Hosted`, `Rehosted` and `NonSpace`; an 'active' lease row in
/// `Fenced`): nothing remembers a revocation once purge deletes its row.
async fn run_state(state: State, conn: sea_orm::DatabaseConnection) {
    let mut violations = Vec::new();
    eprintln!("=== TC-4092 {state:?} ===");
    for line in scenario(state, conn).await {
        eprintln!("{line}");
        if line.starts_with("VIOLATION") {
            violations.push(line);
        }
    }
    assert!(violations.is_empty(), "{state:?}: {violations:#?}");
}

async fn run_sqlite(state: State) {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("tc4092.sqlite").display()
    );
    run_state(state, sea_orm::Database::connect(url).await.unwrap()).await;
}

/// PostgreSQL leg: a private schema on the test server, dropped afterwards.
/// Runs only on GitHub Actions or with `TINYCLOUD_TEST_POSTGRES_URL` and
/// `TINYCLOUD_ALLOW_LOCAL_PG=1` (see `test_support`).
async fn run_postgres(test: &str, state: State) {
    let Some(url) = crate::test_support::postgres_test_url(test) else {
        return;
    };
    let admin = sea_orm::Database::connect(sea_orm::ConnectOptions::new(url.clone()))
        .await
        .unwrap();
    let schema = format!(
        "tc4092s_{}_{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let mut options = sea_orm::ConnectOptions::new(url);
    options
        .max_connections(4)
        .sqlx_logging(false)
        .set_schema_search_path(schema.clone());
    let conn = sea_orm::Database::connect(options).await.unwrap();
    let ran = tokio::spawn(run_state(state, conn)).await;
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
    ran.unwrap();
}

#[tokio::test]
async fn tc4092_hosted_unfenced_a_revoked_purged_chain_is_not_readmitted_on_sqlite() {
    run_sqlite(State::Hosted).await;
}
#[tokio::test]
async fn tc4092_rehosted_b_revoked_purged_chain_is_not_readmitted_on_sqlite() {
    run_sqlite(State::Rehosted).await;
}
#[tokio::test]
async fn tc4092_fenced_c_revoked_purged_chain_leaves_no_lease_or_stamp_on_sqlite() {
    run_sqlite(State::Fenced).await;
}
#[tokio::test]
async fn tc4092_non_space_d_revoked_purged_chain_is_not_readmitted_on_sqlite() {
    run_sqlite(State::NonSpace).await;
}
#[tokio::test]
async fn postgres_tc4092_hosted_unfenced_a_revoked_purged_chain_is_not_readmitted() {
    run_postgres(
        "postgres_tc4092_hosted_unfenced_a_revoked_purged_chain_is_not_readmitted",
        State::Hosted,
    )
    .await;
}
#[tokio::test]
async fn postgres_tc4092_rehosted_b_revoked_purged_chain_is_not_readmitted() {
    run_postgres(
        "postgres_tc4092_rehosted_b_revoked_purged_chain_is_not_readmitted",
        State::Rehosted,
    )
    .await;
}
#[tokio::test]
async fn postgres_tc4092_fenced_c_revoked_purged_chain_leaves_no_lease_or_stamp() {
    run_postgres(
        "postgres_tc4092_fenced_c_revoked_purged_chain_leaves_no_lease_or_stamp",
        State::Fenced,
    )
    .await;
}
#[tokio::test]
async fn postgres_tc4092_non_space_d_revoked_purged_chain_is_not_readmitted() {
    run_postgres(
        "postgres_tc4092_non_space_d_revoked_purged_chain_is_not_readmitted",
        State::NonSpace,
    )
    .await;
}
