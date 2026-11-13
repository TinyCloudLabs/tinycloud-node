//! Refusal and separate-process concurrency conformance for the frozen controls.
mod common;
#[path = "support/renewal_state.rs"]
mod support;
use rocket::http::Status;
use serde_json::{json, Value};
use support::*;
use tinycloud_core::sea_orm::{ConnectionTrait, Statement};

#[tokio::test]
async fn refusal_profiles_leave_state_stamps_and_nonce_reservations_unchanged() {
    let f = fixture(None, 0x11).await;
    let stop = f.auth("stop-renewal", Some(1), "refusal");
    let body = f.body(Some(1));
    let resource = format!("urn:cid:{}", f.lease_cid);
    let action = "tinycloud.delegation/stop-renewal";
    let before = f.snapshot().await;
    let mut cases = vec![(None, body.clone(), Status::Unauthorized, "auth_required")];
    for (claims, status, code) in [
        (
            json!({"aud":key_for_seed(0x33).1}),
            Status::Unauthorized,
            "auth_required",
        ),
        (
            json!({"exp":f.now-1}),
            Status::Unauthorized,
            "auth_required",
        ),
        (
            json!({"nbf":f.now+100}),
            Status::Unauthorized,
            "auth_required",
        ),
        (json!({"nnc":""}), Status::BadRequest, "invalid_request"),
        (
            json!({"prf":[f.lease_cid]}),
            Status::Forbidden,
            "unauthorized_control",
        ),
    ] {
        let auth = resign(&stop, 0x11, |c| {
            for (k, v) in claims.as_object().unwrap() {
                c[k] = v.clone();
            }
        });
        cases.push((Some(auth), body.clone(), status, code));
    }
    for caveats in [
        json!([{}]),
        json!([{}, {}]),
        json!([{"expectedGeneration":1},{}]),
        json!([{"expectedGeneration":1.0}]),
        json!([{"expectedGeneration":-1}]),
        json!([{"expectedGeneration":9007199254740992u64}]),
        json!([{"expectedGeneration":1,"extra":true}]),
    ] {
        cases.push((
            Some(resign(&stop, 0x11, |c| {
                c["att"][&resource][action] = caveats
            })),
            body.clone(),
            Status::BadRequest,
            "invalid_request",
        ));
    }
    let unknown = tinycloud_core::hash::hash(b"wrong signed target")
        .to_cid(0x55)
        .to_string();
    cases.push((
        Some(resign(
            &stop,
            0x11,
            |c| {
                c["att"] = json!({format!("urn:cid:{unknown}"):{action:[{"expectedGeneration":1}]}})
            },
        )),
        body.clone(),
        Status::Forbidden,
        "unauthorized_control",
    ));
    cases.push((
        Some(resign(&stop, 0x11, |c| c["nnc"] = json!("x".repeat(257)))),
        body.clone(),
        Status::BadRequest,
        "invalid_request",
    ));
    cases.push((
        Some(resign(&stop, 0x11, |c| {
            c["att"][&resource]["tinycloud.delegation/status"] = json!([{}])
        })),
        body.clone(),
        Status::BadRequest,
        "invalid_request",
    ));
    let mut invalid_signature = stop.clone().into_bytes();
    let dot = invalid_signature.iter().rposition(|b| *b == b'.').unwrap();
    invalid_signature[dot + 1] = if invalid_signature[dot + 1] == b'A' {
        b'B'
    } else {
        b'A'
    };
    cases.push((
        Some(String::from_utf8(invalid_signature).unwrap()),
        body.clone(),
        Status::Unauthorized,
        "auth_required",
    ));
    let mut wrong_body = body.clone();
    wrong_body["expectedGeneration"] = json!(2);
    cases.push((
        Some(stop.clone()),
        wrong_body,
        Status::Forbidden,
        "unauthorized_control",
    ));
    let mut extra = body.clone();
    extra["state"] = json!("active");
    cases.push((
        Some(stop.clone()),
        extra,
        Status::BadRequest,
        "invalid_request",
    ));
    let mut version = body.clone();
    version["version"] = json!(2);
    cases.push((
        Some(stop.clone()),
        version,
        Status::BadRequest,
        "invalid_request",
    ));
    cases.push((
        Some(f.auth("status", None, "read-with-generation")),
        body.clone(),
        Status::BadRequest,
        "invalid_request",
    ));
    for (auth, body, status, code) in cases {
        let result = f.request(auth, &body).await;
        assert_eq!(result.0, status, "{}", result.1);
        assert_eq!(result.1["code"], code);
        assert_eq!(f.snapshot().await, before);
    }
    let foreign = resign(&stop, 0x22, |_| {});
    let known = f.request(Some(foreign), &body).await;
    let unknown = tinycloud_core::hash::hash(b"unknown lease")
        .to_cid(0x55)
        .to_string();
    let auth =
        resign(
            &stop,
            0x22,
            |c| {
                c["att"] = json!({format!("urn:cid:{unknown}"):{action:[{"expectedGeneration":1}]}})
            },
        );
    let absent = f
        .request(
            Some(auth),
            &json!({"version":1,"leaseCid":unknown,"expectedGeneration":1}),
        )
        .await;
    assert_eq!(known, absent);
    assert_eq!(known.0, Status::Forbidden);
    assert_eq!(f.snapshot().await, before);
    // A fresh valid signature cannot reuse a nonce committed by an owner read.
    assert_eq!(
        f.request(Some(f.auth("status", None, "shared")), &f.body(None))
            .await
            .0,
        Status::Ok
    );
    let before = f.snapshot().await;
    let replay = f
        .request(Some(f.auth("stop-renewal", Some(1), "shared")), &body)
        .await;
    assert_eq!(replay.1["code"], "invocation_replay");
    assert_eq!(f.snapshot().await, before);
    // Same-state and stale CAS requests cannot create stamps or consume a nonce.
    let same = f
        .request(Some(f.auth("enable-renewal", Some(1), "same")), &body)
        .await;
    assert_eq!(same.1["code"], "renewal_state_conflict");
    assert_eq!(f.snapshot().await, before);
}

#[tokio::test]
async fn both_original_and_signed_lease_issuers_are_required() {
    let f = fixture(None, 0x22).await;
    for seed in [0x11, 0x22] {
        for (action, generation) in [("status", None), ("stop-renewal", Some(1))] {
            let before = f.snapshot().await;
            let auth = resign(&f.auth(action, generation, "misregistered"), seed, |_| {});
            let result = f.request(Some(auth), &f.body(generation)).await;
            assert_eq!(result.0, Status::Forbidden, "{}", result.1);
            assert_eq!(result.1["code"], "unauthorized_control");
            assert_eq!(f.snapshot().await, before);
        }
    }
}

// This entry point runs only in child processes spawned below. Each child opens
// its own node/pool; no process-local mutex can satisfy these assertions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn process_worker() {
    let Ok(url) = std::env::var("RENEWAL_TEST_CHILD_URL") else {
        return;
    };
    let action = std::env::var("RENEWAL_TEST_CHILD_ACTION").unwrap();
    let lease = std::env::var("RENEWAL_TEST_CHILD_LEASE").unwrap();
    let original = std::env::var("RENEWAL_TEST_CHILD_ORIGINAL").unwrap();
    let result = std::env::var("RENEWAL_TEST_CHILD_RESULT").unwrap();
    let (client, _dir) = node(Some(&url)).await;
    let db = client.rocket().state::<tinycloud::TinyCloud>().unwrap();
    let identity = db.renewal_identity().unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let nonce = format!("process-{}", std::process::id());
    let output = if action == "renew" {
        // Deliberately observe active state BEFORE issue_stamp takes its lock.
        let cached =
            tinycloud_core::renewal::lease_for_original(db.connection(), &original, identity)
                .await
                .unwrap();
        let secret = tinycloud_core::keys::StaticSecret::new(vec![0x42; 32]).unwrap();
        let seed = secret.derive_key(tinycloud_core::renewal::RENEWER_KEY_CONTEXT);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let jwk = serde_json::from_value(json!({"kty":"OKP","crv":"Ed25519","alg":"EdDSA",
            "x":base64::encode_config(signing.verifying_key().to_bytes(),base64::URL_SAFE_NO_PAD),
            "d":base64::encode_config(seed,base64::URL_SAFE_NO_PAD)}))
        .unwrap();
        let method = format!(
            "{}#{}",
            identity.renewer_did,
            identity.renewer_did.rsplit(':').next().unwrap()
        );
        let invocation = tinycloud_auth::authorization::make_invocation_from_uris(
            [(
                format!("urn:cid:{original}").parse().unwrap(),
                ["tinycloud.delegation/renew".parse().unwrap()],
            )],
            &lease.parse().unwrap(),
            &jwk,
            &method,
            (now + 50) as f64,
            tinycloud_auth::authorization::InvocationOptions {
                nonce: Some(nonce.clone()),
                proof: Some(vec![lease.parse().unwrap()]),
                ..Default::default()
            },
        )
        .unwrap();
        let issued = db
            .issue_renewal_stamp(tinycloud_core::renewal::StampIssue {
                invocation: invocation.try_into().unwrap(),
                original_cid: original,
                lease_cid: lease,
                replay_hash: tinycloud_core::hash::hash(nonce.as_bytes()),
                replay_expires_at: now + 50,
            })
            .await;
        json!({"ok":issued.is_ok(),"cachedActive":cached.is_some(),"generation":issued.as_ref().ok().map(|s|s.generation)})
    } else if action.starts_with("revoke-") {
        let target = if action == "revoke-original" {
            &original
        } else {
            &lease
        };
        let auth = token(
            &identity.stable_node_did,
            &format!("urn:cid:{target}"),
            "tinycloud.delegation/revoke",
            None,
            &nonce,
            now + 50,
        );
        let response = client
            .post("/revoke")
            .header(rocket::http::Header::new("Authorization", auth))
            .dispatch()
            .await;
        json!({"status":response.status().code,"body":response.into_string().await})
    } else {
        let generation = std::env::var("RENEWAL_TEST_CHILD_GENERATION")
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let auth = token(
            &identity.stable_node_did,
            &format!("urn:cid:{lease}"),
            &format!("tinycloud.delegation/{action}"),
            Some(generation),
            &nonce,
            now + 50,
        );
        let response = client
            .post("/delegation/renewal/state")
            .header(rocket::http::ContentType::JSON)
            .header(rocket::http::Header::new("Authorization", auth))
            .json(&json!({"version":1,"leaseCid":lease,"expectedGeneration":generation}))
            .dispatch()
            .await;
        json!({"status":response.status().code,"body":response.into_json::<Value>().await})
    };
    std::fs::write(result, serde_json::to_vec(&output).unwrap()).unwrap();
}

fn child(
    f: &Fixture,
    url: &str,
    action: &str,
    generation: u64,
    path: &std::path::Path,
) -> tokio::process::Child {
    tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "process_worker", "--nocapture"])
        .env("RENEWAL_TEST_CHILD_URL", url)
        .env("RENEWAL_TEST_CHILD_ACTION", action)
        .env("RENEWAL_TEST_CHILD_LEASE", &f.lease_cid)
        .env("RENEWAL_TEST_CHILD_ORIGINAL", &f.original_cid)
        .env("RENEWAL_TEST_CHILD_RESULT", path)
        .env("RENEWAL_TEST_CHILD_GENERATION", generation.to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}
async fn result(child: tokio::process::Child, path: &std::path::Path) -> Value {
    let output = tokio::time::timeout(std::time::Duration::from_secs(45), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
async fn wait_for_lock_waiters(conn: &tinycloud_core::RecoveringConnection, key: i64, count: i64) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let row=conn.query_one(Statement::from_sql_and_values(tinycloud_core::sea_orm::DatabaseBackend::Postgres,
            "SELECT count(*) AS n FROM pg_locks WHERE locktype='advisory' AND classid=$1::bigint::oid AND objid=$2::bigint::oid AND NOT granted",
            [((key as u64>>32) as i64).into(),((key as u64&0xffffffff) as i64).into()])).await.unwrap().unwrap();
        if row.try_get::<i64>("", "n").unwrap() >= count {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "processes did not contend for the original lock"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_separate_processes_serialize_stop_enable_and_stamp_issuance() {
    use tinycloud_core::sea_orm::{Database, DatabaseBackend, TransactionTrait};
    let Some(url) = common::postgres_test_url(
        "postgres_separate_processes_serialize_stop_enable_and_stamp_issuance",
    ) else {
        return;
    };
    let admin = Database::connect(&url).await.unwrap();
    for (index, actions) in [
        vec![("stop-renewal", 1), ("stop-renewal", 1)],
        vec![("stop-renewal", 1), ("renew", 1)],
        vec![("renew", 1), ("stop-renewal", 1)],
        vec![("stop-renewal", 1), ("enable-renewal", 2), ("renew", 1)],
    ]
    .into_iter()
    .enumerate()
    {
        let schema = format!(
            "renewal_race_{}_{}_{}",
            std::process::id(),
            index,
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        admin
            .execute(Statement::from_string(
                DatabaseBackend::Postgres,
                format!("CREATE SCHEMA {schema}"),
            ))
            .await
            .unwrap();
        let mut shared = reqwest::Url::parse(&url).unwrap();
        shared
            .query_pairs_mut()
            .append_pair("options", &format!("-c search_path={schema}"));
        let shared = shared.to_string();
        let f = fixture(Some(&shared), 0x11).await;
        let conn = f.db().connection();
        conn.execute_unprepared("DELETE FROM renewal_stamp")
            .await
            .unwrap();
        let digest = tinycloud_core::hash::hash(f.original_id.as_ref());
        let key = i64::from_be_bytes(digest.as_ref()[..8].try_into().unwrap());
        let tx = conn.begin().await.unwrap();
        tx.query_one(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT pg_advisory_xact_lock($1)",
            [key.into()],
        ))
        .await
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut children = Vec::new();
        for (i, (action, generation)) in actions.iter().enumerate() {
            let path = dir.path().join(format!("{i}.json"));
            let child = child(&f, &shared, action, *generation, &path);
            children.push((child, path));
            wait_for_lock_waiters(conn, key, (i + 1) as i64).await;
        }
        tx.commit().await.unwrap();
        let mut outputs = Vec::new();
        for (child, path) in children {
            outputs.push(result(child, &path).await);
        }
        if index == 0 {
            assert_eq!(outputs[0]["status"], 200);
            assert_eq!(outputs[1]["status"], 409);
            assert_eq!(outputs[1]["body"]["code"], "renewal_state_conflict");
        } else if index == 1 {
            assert_eq!(outputs[0]["status"], 200);
            assert_eq!(outputs[1]["cachedActive"], true);
            assert_eq!(outputs[1]["ok"], false);
            assert_eq!(f.snapshot().await["stamps"], 0);
        } else if index == 2 {
            assert_eq!(outputs[0]["ok"], true);
            assert_eq!(outputs[1]["status"], 200);
            assert_eq!(f.snapshot().await["stamps"], 1);
            assert!(
                f.db()
                    .delegation_effective_expiry(f.original_id, f.now)
                    .await
                    .unwrap()
                    .unwrap()
                    > f.now + 3600
            );
        } else {
            assert_eq!(outputs[0]["status"], 200);
            assert_eq!(outputs[1]["status"], 200);
            assert_eq!(outputs[2]["cachedActive"], true);
            assert_eq!(outputs[2]["ok"], true);
            assert_eq!(outputs[2]["generation"], 3);
        }
        conn.sea_orm_connection()
            .get_postgres_connection_pool()
            .close()
            .await;
        admin
            .execute(Statement::from_string(
                DatabaseBackend::Postgres,
                format!("DROP SCHEMA {schema} CASCADE"),
            ))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn expired_authority_and_generation_overflow_cannot_be_enabled() {
    for (age, code) in [(-8000, "lease_expired"), (-4000, "grant_expired")] {
        let f = fixture_at(None, 0x11, age).await;
        let before = f.snapshot().await;
        let result = f
            .request(
                Some(f.auth("enable-renewal", Some(1), "expired")),
                &f.body(Some(1)),
            )
            .await;
        assert_eq!(result.0, Status::Conflict, "{}", result.1);
        assert_eq!(result.1["code"], code);
        assert_eq!(f.snapshot().await, before);
    }
    let f = fixture(None, 0x11).await;
    let conn = f.db().connection();
    let max = (1i64 << 53) - 1;
    conn.execute(Statement::from_sql_and_values(
        conn.get_database_backend(),
        "UPDATE renewal_lease SET generation=$1 WHERE lease_cid=$2",
        [max.into(), Vec::<u8>::from(f.lease_id).into()],
    ))
    .await
    .unwrap();
    let before = f.snapshot().await;
    let result = f
        .request(
            Some(f.auth("stop-renewal", Some(max as u64), "overflow")),
            &f.body(Some(max as u64)),
        )
        .await;
    assert_eq!(result.1["code"], "renewal_state_conflict");
    assert_eq!(f.snapshot().await, before);
    conn.execute_unprepared("UPDATE renewal_identity SET epoch=epoch+1")
        .await
        .unwrap();
    let result = f
        .request(
            Some(f.auth("stop-renewal", Some(max as u64), "identity")),
            &f.body(Some(max as u64)),
        )
        .await;
    assert_eq!(result.1["code"], "renewer_identity_changed");
    assert_eq!(f.snapshot().await, before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_separate_process_enable_cannot_override_revocation() {
    use tinycloud_core::sea_orm::{Database, DatabaseBackend, TransactionTrait};
    let Some(url) =
        common::postgres_test_url("postgres_separate_process_enable_cannot_override_revocation")
    else {
        return;
    };
    let admin = Database::connect(&url).await.unwrap();
    for (index, target) in ["original", "lease"].into_iter().enumerate() {
        let schema = format!(
            "renewal_revoke_{}_{}_{}",
            std::process::id(),
            index,
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        admin
            .execute(Statement::from_string(
                DatabaseBackend::Postgres,
                format!("CREATE SCHEMA {schema}"),
            ))
            .await
            .unwrap();
        let mut shared = reqwest::Url::parse(&url).unwrap();
        shared
            .query_pairs_mut()
            .append_pair("options", &format!("-c search_path={schema}"));
        let shared = shared.to_string();
        let f = fixture(Some(&shared), 0x11).await;
        assert_eq!(
            f.request(
                Some(f.auth("stop-renewal", Some(1), "stop")),
                &f.body(Some(1))
            )
            .await
            .0,
            Status::Ok
        );
        let conn = f.db().connection();
        let digest = tinycloud_core::hash::hash(f.original_id.as_ref());
        let key = i64::from_be_bytes(digest.as_ref()[..8].try_into().unwrap());
        let tx = conn.begin().await.unwrap();
        tx.query_one(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT pg_advisory_xact_lock($1)",
            [key.into()],
        ))
        .await
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let enable_path = dir.path().join("enable.json");
        let revoke_path = dir.path().join("revoke.json");
        let enable = child(&f, &shared, "enable-renewal", 2, &enable_path);
        wait_for_lock_waiters(conn, key, 1).await;
        let revoke = child(&f, &shared, &format!("revoke-{target}"), 2, &revoke_path);
        let revoked = result(revoke, &revoke_path).await;
        assert_eq!(revoked["status"], 200, "{revoked}");
        tx.commit().await.unwrap();
        let enabled = result(enable, &enable_path).await;
        assert_eq!(enabled["status"], 409, "{enabled}");
        let expected = if target == "original" {
            "grant_revoked"
        } else {
            "lease_revoked"
        };
        assert_eq!(enabled["body"]["code"], expected);
        assert_eq!(f.snapshot().await["generation"], 2);
        assert_eq!(f.snapshot().await["state"], "stopped");
        let before = f.snapshot().await;
        let denied = f
            .request(
                Some(f.auth("enable-renewal", Some(2), "after-revoke")),
                &f.body(Some(2)),
            )
            .await;
        assert_eq!(denied.0, Status::Conflict);
        assert_eq!(f.snapshot().await, before);
        conn.sea_orm_connection()
            .get_postgres_connection_pool()
            .close()
            .await;
        admin
            .execute(Statement::from_string(
                DatabaseBackend::Postgres,
                format!("DROP SCHEMA {schema} CASCADE"),
            ))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn registration_starts_active_and_cannot_reset_or_bypass_a_stop() {
    let f = fixture(None, 0x11).await;
    let conn = f.db().connection();
    let backend = conn.get_database_backend();
    let row = conn
        .query_one(Statement::from_sql_and_values(
            backend,
            "SELECT serialization FROM delegation WHERE id=$1",
            [Vec::<u8>::from(f.lease_id).into()],
        ))
        .await
        .unwrap()
        .unwrap();
    let lease = String::from_utf8(row.try_get::<Vec<u8>>("", "serialization").unwrap()).unwrap();
    conn.execute_unprepared("DELETE FROM renewal_stamp")
        .await
        .unwrap();
    conn.execute_unprepared("DELETE FROM renewal_lease")
        .await
        .unwrap();
    let response = f
        .client
        .post("/delegate")
        .header(rocket::http::Header::new("Authorization", lease.clone()))
        .dispatch()
        .await;
    let status = response.status();
    let text = response.into_string().await.unwrap_or_default();
    assert!(status.class().is_success(), "{status}: {text}");
    assert_eq!(f.snapshot().await["state"], "active");
    assert_eq!(f.snapshot().await["generation"], 1);
    assert_eq!(
        f.request(
            Some(f.auth("stop-renewal", Some(1), "stop")),
            &f.body(Some(1))
        )
        .await
        .0,
        Status::Ok
    );
    let before = f.snapshot().await;
    let repeated = f
        .client
        .post("/delegate")
        .header(rocket::http::Header::new("Authorization", lease.clone()))
        .dispatch()
        .await;
    assert!(repeated.status().class().is_success());
    assert_eq!(f.snapshot().await, before);
    let different = resign(&lease, 0x11, |c| {
        c["nnc"] = json!("separately-authorized-lease")
    });
    let refused = f
        .client
        .post("/delegate")
        .header(rocket::http::Header::new("Authorization", different))
        .dispatch()
        .await;
    assert!(!refused.status().class().is_success());
    assert_eq!(f.snapshot().await, before);
}

#[tokio::test]
async fn owner_controls_require_fresh_nbf_and_a_sixty_second_lifetime() {
    for profile in ["missing-nbf", "old-nbf", "sixty-one-seconds"] {
        let f = fixture(None, 0x11).await;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let auth = resign(&f.auth("stop-renewal", Some(1), profile), 0x11, |c| {
            c["exp"] = json!(now + 30);
            match profile {
                "missing-nbf" => {
                    c.as_object_mut().unwrap().remove("nbf");
                }
                "old-nbf" => c["nbf"] = json!(now - 1000),
                _ => c["nbf"] = json!(now - 31),
            }
        });
        let before = f.snapshot().await;
        let response = f.request(Some(auth), &f.body(Some(1))).await;
        assert_eq!(
            response.0,
            Status::Unauthorized,
            "{profile}: {}",
            response.1
        );
        assert_eq!(response.1["code"], "auth_required");
        assert_eq!(f.snapshot().await, before);
    }
    let f = fixture(None, 0x11).await;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let auth = resign(&f.auth("stop-renewal", Some(1), "exact-sixty"), 0x11, |c| {
        c["nbf"] = json!(now - 30);
        c["exp"] = json!(now + 30);
    });
    assert_eq!(f.request(Some(auth), &f.body(Some(1))).await.0, Status::Ok);
}

#[tokio::test]
async fn signed_duplicate_abilities_and_nonraw_cid_aliases_are_refused() {
    use ed25519_dalek::Signer;
    let f = fixture(None, 0x11).await;
    let token = f.auth("stop-renewal", Some(1), "duplicate");
    let parts = token.split('.').collect::<Vec<_>>();
    let claims: Value =
        serde_json::from_slice(&base64::decode_config(parts[1], base64::URL_SAFE_NO_PAD).unwrap())
            .unwrap();
    let att = serde_json::to_string(&claims["att"]).unwrap();
    let duplicate = format!(
        r#"{{"urn:cid:{}":{{"tinycloud.delegation/stop-renewal":[{{"expectedGeneration":1}}],"tinycloud.delegation/stop-renewal":[{{"expectedGeneration":1}}]}}}}"#,
        f.lease_cid
    );
    let raw = serde_json::to_string(&claims)
        .unwrap()
        .replace(&att, &duplicate);
    let input = format!(
        "{}.{}",
        parts[0],
        base64::encode_config(raw, base64::URL_SAFE_NO_PAD)
    );
    let signature = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]).sign(input.as_bytes());
    let duplicate_token = format!(
        "{input}.{}",
        base64::encode_config(signature.to_bytes(), base64::URL_SAFE_NO_PAD)
    );
    let before = f.snapshot().await;
    let refused = f.request(Some(duplicate_token), &f.body(Some(1))).await;
    assert_eq!(refused.0, Status::BadRequest, "{}", refused.1);
    assert_eq!(f.snapshot().await, before);
    let cid = f
        .lease_cid
        .parse::<tinycloud_auth::authorization::Cid>()
        .unwrap();
    let alias = tinycloud_auth::authorization::Cid::new_v1(0x71, *cid.hash()).to_string();
    let auth = resign(
        &token,
        0x11,
        |c| c["att"] = json!({format!("urn:cid:{alias}"):{"tinycloud.delegation/stop-renewal":[{"expectedGeneration":1}]}}),
    );
    let refused = f
        .request(
            Some(auth),
            &json!({"version":1,"leaseCid":alias,"expectedGeneration":1}),
        )
        .await;
    assert_eq!(refused.0, Status::BadRequest, "{}", refused.1);
    assert_eq!(f.snapshot().await, before);
    let auth = resign(
        &token,
        0x11,
        |c| c["att"] = json!({format!("urn:cid:{}",f.lease_cid):{"tinycloud.delegation/revoke":[{"expectedGeneration":1}]}}),
    );
    let refused = f.request(Some(auth), &f.body(Some(1))).await;
    assert_eq!(refused.0, Status::Forbidden, "{}", refused.1);
    assert_eq!(f.snapshot().await, before);
}

#[tokio::test]
async fn database_failure_rolls_back_the_reserved_nonce_and_exposes_no_database_text() {
    let f = fixture(None, 0x11).await;
    let conn = f.db().connection();
    conn.execute_unprepared("CREATE TRIGGER refuse_state_update BEFORE UPDATE ON renewal_lease BEGIN SELECT RAISE(ABORT, 'injected database failure'); END").await.unwrap();
    let before = f.snapshot().await;
    let response = f
        .request(
            Some(f.auth("stop-renewal", Some(1), "transaction-failure")),
            &f.body(Some(1)),
        )
        .await;
    assert_eq!(response.0, Status::ServiceUnavailable);
    assert_eq!(response.1["code"], "renewal_state_unavailable");
    assert!(!response.1.to_string().contains("injected"));
    assert_eq!(f.snapshot().await, before);
    conn.execute_unprepared("DROP TRIGGER refuse_state_update")
        .await
        .unwrap();
    assert_eq!(
        f.request(
            Some(f.auth("stop-renewal", Some(1), "transaction-failure")),
            &f.body(Some(1))
        )
        .await
        .0,
        Status::Ok
    );
}

#[tokio::test]
async fn actual_holder_and_renewer_signatures_do_not_authorize_owner_controls() {
    let f = fixture(None, 0x11).await;
    let secret = tinycloud_core::keys::StaticSecret::new(vec![0x42; 32]).unwrap();
    let identity = f.db().renewal_identity().unwrap();
    for (context, expected_did) in [
        (
            b"tinycloud/node/identity".as_slice(),
            &identity.stable_node_did,
        ),
        (
            tinycloud_core::renewal::RENEWER_KEY_CONTEXT,
            &identity.renewer_did,
        ),
    ] {
        let seed = secret.derive_key(context);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let jwk: tinycloud_auth::ssi::jwk::JWK =
            serde_json::from_value(json!({"kty":"OKP","crv":"Ed25519","alg":"EdDSA",
            "x":base64::encode_config(signing.verifying_key().to_bytes(),base64::URL_SAFE_NO_PAD),
            "d":base64::encode_config(seed,base64::URL_SAFE_NO_PAD)}))
            .unwrap();
        assert_eq!(
            tinycloud_auth::resolver::DID_METHODS
                .generate(&jwk, "key")
                .unwrap()
                .as_str(),
            expected_did
        );
        let method = format!(
            "{}#{}",
            expected_did,
            expected_did.rsplit(':').next().unwrap()
        );
        for (action, generation) in [("status", None), ("stop-renewal", Some(1))] {
            let token = f.auth(action, generation, "not-management");
            let invocation =
                tinycloud_auth::authorization::TinyCloudInvocation::decode(&token).unwrap();
            let mut claims = invocation.payload().clone();
            claims.issuer = method.parse().unwrap();
            let auth = claims
                .sign(tinycloud_auth::ssi::jwk::Algorithm::EdDSA, &jwk)
                .unwrap()
                .encode()
                .unwrap();
            let before = f.snapshot().await;
            let refused = f.request(Some(auth), &f.body(generation)).await;
            assert_eq!(refused.0, Status::Forbidden);
            assert_eq!(refused.1["code"], "unauthorized_control");
            assert_eq!(f.snapshot().await, before);
        }
    }
}

#[tokio::test]
async fn ambiguous_historical_live_leases_refuse_without_partial_stop() {
    let f = fixture(None, 0x11).await;
    let conn = f.db().connection();
    let backend = conn.get_database_backend();
    let row = conn
        .query_one(Statement::from_sql_and_values(
            backend,
            "SELECT serialization FROM delegation WHERE id=$1",
            [Vec::<u8>::from(f.lease_id).into()],
        ))
        .await
        .unwrap()
        .unwrap();
    let lease = String::from_utf8(row.try_get::<Vec<u8>>("", "serialization").unwrap()).unwrap();
    let other = resign(&lease, 0x11, |c| {
        c["nnc"] = json!("historical-second-lease")
    });
    let other_id = tinycloud_core::hash::hash(other.as_bytes());
    conn.execute(Statement::from_sql_and_values(backend,
        "INSERT INTO delegation (id,delegator,delegatee,expiry,issued_at,not_before,facts,serialization,serialization_format) SELECT $1,delegator,delegatee,expiry,issued_at,not_before,facts,$2,0 FROM delegation WHERE id=$3",
        [Vec::<u8>::from(other_id).into(),other.into_bytes().into(),Vec::<u8>::from(f.lease_id).into()])).await.unwrap();
    conn.execute(Statement::from_sql_and_values(
        backend,
        "INSERT INTO delegation_cid_alias (id,canonical,encrypted) VALUES ($1,$1,FALSE)",
        [Vec::<u8>::from(other_id).into()],
    ))
    .await
    .unwrap();
    conn.execute(Statement::from_sql_and_values(backend,
        "INSERT INTO ability (delegation,resource,ability,caveats) SELECT $1,resource,ability,caveats FROM ability WHERE delegation=$2",
        [Vec::<u8>::from(other_id).into(),Vec::<u8>::from(f.lease_id).into()])).await.unwrap();
    conn.execute(Statement::from_sql_and_values(backend,
        "INSERT INTO renewal_lease (original_canonical,lease_cid,state,generation,grantor,renewer_did,renewer_epoch,lease_expiry,original_expiry,period_seconds,audience_public_key) SELECT original_canonical,$1,state,generation,grantor,renewer_did,renewer_epoch,lease_expiry,original_expiry,period_seconds,audience_public_key FROM renewal_lease WHERE lease_cid=$2",
        [Vec::<u8>::from(other_id).into(),Vec::<u8>::from(f.lease_id).into()])).await.unwrap();
    let before = f.snapshot().await;
    let refused = f
        .request(
            Some(f.auth("stop-renewal", Some(1), "ambiguous")),
            &f.body(Some(1)),
        )
        .await;
    assert_eq!(refused.0, Status::Conflict);
    assert_eq!(refused.1["code"], "ambiguous_renewal_lease");
    assert_eq!(f.snapshot().await, before);
    let rows = conn
        .query_all(Statement::from_string(
            backend,
            "SELECT state,generation FROM renewal_lease",
        ))
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(row.try_get::<String>("", "state").unwrap(), "active");
        assert_eq!(row.try_get::<i64>("", "generation").unwrap(), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_enable_receipt_cannot_outlive_a_competing_revocation() {
    use tinycloud_core::sea_orm::{Database, DatabaseBackend, TransactionTrait};
    let Some(url) =
        common::postgres_test_url("postgres_enable_receipt_cannot_outlive_a_competing_revocation")
    else {
        return;
    };
    let admin = Database::connect(&url).await.unwrap();
    for (index, target) in ["original", "lease"].into_iter().enumerate() {
        let schema = format!(
            "renewal_receipt_{}_{}_{}",
            std::process::id(),
            index,
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        admin
            .execute(Statement::from_string(
                DatabaseBackend::Postgres,
                format!("CREATE SCHEMA {schema}"),
            ))
            .await
            .unwrap();
        let mut shared = reqwest::Url::parse(&url).unwrap();
        shared
            .query_pairs_mut()
            .append_pair("options", &format!("-c search_path={schema}"));
        let shared = shared.to_string();
        let f = fixture(Some(&shared), 0x11).await;
        assert_eq!(
            f.request(
                Some(f.auth("stop-renewal", Some(1), "stop-before-race")),
                &f.body(Some(1))
            )
            .await
            .0,
            Status::Ok
        );
        let conn = f.db().connection();
        let target_id = if target == "original" {
            f.original_id
        } else {
            f.lease_id
        };
        let tx = conn.begin().await.unwrap();
        // The real revocation INSERT's FK must wait for this target row;
        // owner control only reads the signed graph and can commit meanwhile.
        tx.query_one(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT id FROM delegation WHERE id=$1 FOR UPDATE",
            [Vec::<u8>::from(target_id).into()],
        ))
        .await
        .unwrap();
        let pid = tx
            .query_one(Statement::from_string(
                DatabaseBackend::Postgres,
                "SELECT pg_backend_pid() AS pid",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i32>("", "pid")
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let revoke_path = dir.path().join("revoke.json");
        let enable_path = dir.path().join("enable.json");
        let revoke = child(&f, &shared, &format!("revoke-{target}"), 2, &revoke_path);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let row=conn.query_one(Statement::from_sql_and_values(DatabaseBackend::Postgres,
                "SELECT count(*) AS n FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))",[pid.into()])).await.unwrap().unwrap();
            if row.try_get::<i64>("", "n").unwrap() > 0 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "revocation did not wait on the target FK"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let enable = child(&f, &shared, "enable-renewal", 2, &enable_path);
        let receipt = result(enable, &enable_path).await;
        assert_eq!(receipt["status"], 200, "{receipt}");
        assert_eq!(receipt["body"]["generation"], 3);
        tx.commit().await.unwrap();
        let revoked = result(revoke, &revoke_path).await;
        assert_eq!(revoked["status"], 200, "{revoked}");
        let target_cid = if target == "original" {
            &f.original_cid
        } else {
            &f.lease_cid
        };
        let auth = resign(&f.auth("status", None, "authoritative-status"), 0x11, |c| {
            c["att"] = json!({format!("urn:cid:{target_cid}"):{"tinycloud.delegation/status":[{}]}})
        });
        let response = f
            .client
            .post("/delegation/status")
            .header(rocket::http::ContentType::JSON)
            .header(rocket::http::Header::new("Authorization", auth))
            .json(&json!({"cid":target_cid}))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let status = response.into_json::<Value>().await.unwrap();
        assert_eq!(status["revoked"], true);
        assert_eq!(status["active"], false);
        if target == "lease" {
            assert_eq!(
                f.db()
                    .delegation_effective_expiry(f.original_id, f.now)
                    .await
                    .unwrap(),
                Some(f.now + 3600)
            );
        }
        let before = f.snapshot().await;
        let refused = f
            .request(
                Some(f.auth("stop-renewal", Some(3), "after-winning-revoke")),
                &f.body(Some(3)),
            )
            .await;
        assert_eq!(refused.0, Status::Conflict);
        assert_eq!(f.snapshot().await, before);
        conn.sea_orm_connection()
            .get_postgres_connection_pool()
            .close()
            .await;
        admin
            .execute(Statement::from_string(
                DatabaseBackend::Postgres,
                format!("DROP SCHEMA {schema} CASCADE"),
            ))
            .await
            .unwrap();
    }
}
