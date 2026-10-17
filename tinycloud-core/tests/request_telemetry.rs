use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::keys::StaticSecret;
use tinycloud_core::request_telemetry::{current, scope, RequestContext};
use tinycloud_core::telemetry::Pseudonymizer;

fn pseudonymizer(secret: u8) -> Arc<Pseudonymizer> {
    Arc::new(Pseudonymizer::new(
        &StaticSecret::new(vec![secret; 32]).unwrap(),
    ))
}

fn request(pseudonymizer: Arc<Pseudonymizer>) -> Arc<RequestContext> {
    RequestContext::new(
        "12345678-1234-4234-8234-123456789abc".parse().unwrap(),
        pseudonymizer,
    )
}

#[test]
fn hashes_match_exact_canonical_domain_separated_hmac() {
    let secret = StaticSecret::new(vec![17; 32]).unwrap();
    let context = request(Arc::new(Pseudonymizer::new(&secret)));
    let space: SpaceId =
        "tinycloud:pkh:eip155:1:0x1234567890123456789012345678901234567890:private"
            .parse()
            .unwrap();
    context.observe_space(&space);
    let key = secret.derive_key(b"tinycloud/telemetry/pseudonyms/v1");
    let mut account = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    account.update(b"account\0");
    account.update(space.did().as_str().as_bytes());
    let mut canonical_space = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    canonical_space.update(b"space\0");
    canonical_space.update(space.to_string().as_bytes());
    let hashes = context.hashes();
    assert_eq!(
        hashes.account_hash,
        Some(account.finalize().into_bytes().into())
    );
    assert_eq!(
        hashes.space_hash,
        Some(canonical_space.finalize().into_bytes().into())
    );
    assert_ne!(hashes.account_hash, hashes.space_hash);
    assert_eq!(
        context.request_id().to_string(),
        "12345678-1234-4234-8234-123456789abc"
    );
    context.observe_space(&space);
    assert_eq!(context.hashes(), hashes);
}

#[test]
fn shared_pseudonyms_match_literal_interoperability_vectors() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/telemetry-pseudonyms.json")).unwrap();
    let secret =
        StaticSecret::new(hex::decode(fixtures["synthetic_secret_hex"].as_str().unwrap()).unwrap())
            .unwrap();
    let pseudonymizer = Pseudonymizer::new(&secret);
    for case in fixtures["identities"].as_array().unwrap() {
        let space: SpaceId = case["space"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            hex::encode(pseudonymizer.account_hash(&space).into_bytes()),
            case["account_hash"].as_str().unwrap(),
            "{}",
            case["id"],
        );
        assert_eq!(
            hex::encode(pseudonymizer.space_hash(&space).into_bytes()),
            case["space_hash"].as_str().unwrap(),
            "{}",
            case["id"],
        );
    }
    let cases = fixtures["databases"].as_array().unwrap();
    let pair = fixtures["old_separator_collision_pair"].as_array().unwrap();
    let mut collision_hashes = [None, None];
    for case in cases {
        let space: SpaceId = case["space"].as_str().unwrap().parse().unwrap();
        let hash = pseudonymizer
            .db_hash(
                case["service"].as_str().unwrap(),
                &space,
                case["physical_name"].as_str().unwrap(),
            )
            .unwrap();
        assert_eq!(
            hex::encode(hash.clone().into_bytes()),
            case["db_hash"].as_str().unwrap(),
            "{}",
            case["id"],
        );
        if let Some(index) = pair.iter().position(|id| *id == case["id"]) {
            collision_hashes[index] = Some(hash);
        }
    }
    let old_payload = |id: &serde_json::Value| {
        let case = cases.iter().find(|case| case["id"] == *id).unwrap();
        ["service", "space", "physical_name"]
            .map(|field| case[field].as_str().unwrap())
            .join("\0")
    };
    // This is a real ambiguity in the old encoding, not merely two different inputs.
    assert_eq!(old_payload(&pair[0]), old_payload(&pair[1]));
    assert_ne!(collision_hashes[0], collision_hashes[1]);
}

#[test]
fn multispace_omits_only_conflicting_identity_hashes_permanently() {
    let context = request(pseudonymizer(3));
    assert_eq!(context.hashes().account_hash, None);
    assert_eq!(context.hashes().space_hash, None);
    let first: SpaceId = "tinycloud:pkh:eip155:1:0x1234567890123456789012345678901234567890:first"
        .parse()
        .unwrap();
    let same_account: SpaceId =
        "tinycloud:pkh:eip155:1:0x1234567890123456789012345678901234567890:second"
            .parse()
            .unwrap();
    let different_account: SpaceId =
        "tinycloud:pkh:eip155:1:0x9876543210987654321098765432109876543210:first"
            .parse()
            .unwrap();
    context.observe_space(&first);
    let hashes = context.hashes();
    assert!(hashes.account_hash.is_some());
    assert!(hashes.space_hash.is_some());
    context.observe_space(&same_account);
    assert_eq!(context.hashes().account_hash, hashes.account_hash);
    assert_eq!(context.hashes().space_hash, None);
    context.observe_space(&different_account);
    assert_eq!(context.hashes().account_hash, None);
    assert_eq!(context.hashes().space_hash, None);
    context.observe_space(&first);
    assert_eq!(context.hashes().account_hash, None);
    assert_eq!(context.hashes().space_hash, None);
}

#[test]
fn pseudonyms_are_stable_for_secret_and_differ_across_secrets() {
    let space: SpaceId =
        "tinycloud:pkh:eip155:1:0x1234567890123456789012345678901234567890:private"
            .parse()
            .unwrap();
    let first = request(pseudonymizer(7));
    let repeated = request(pseudonymizer(7));
    let rotated = request(pseudonymizer(8));
    for context in [&first, &repeated, &rotated] {
        context.observe_space(&space);
    }
    assert_eq!(first.hashes(), repeated.hashes());
    assert_ne!(first.hashes().account_hash, rotated.hashes().account_hash);
    assert_ne!(first.hashes().space_hash, rotated.hashes().space_hash);
}

#[test]
fn synchronous_worker_entry_restores_both_context_and_metrics() {
    use tinycloud_core::request_telemetry::enter;
    let outer = request(pseudonymizer(1));
    let inner = request(pseudonymizer(2));
    {
        let _outer = enter(Some(Arc::clone(&outer)));
        assert!(Arc::ptr_eq(&current().unwrap(), &outer));
        assert!(Arc::ptr_eq(
            &sqlx_core::request_telemetry::current().unwrap(),
            &outer.metrics(),
        ));
        {
            let _inner = enter(Some(Arc::clone(&inner)));
            assert!(Arc::ptr_eq(&current().unwrap(), &inner));
            let _clear = enter(None);
            assert!(current().is_none());
            assert!(sqlx_core::request_telemetry::current().is_none());
        }
        assert!(Arc::ptr_eq(&current().unwrap(), &outer));
        assert!(Arc::ptr_eq(
            &sqlx_core::request_telemetry::current().unwrap(),
            &outer.metrics(),
        ));
    }
    assert!(current().is_none());
    assert!(sqlx_core::request_telemetry::current().is_none());
}

#[tokio::test]
async fn request_scope_restores_context_and_drives_sqlx_metrics() {
    use sea_orm::sqlx::Executor;
    let pool = sea_orm::sqlx::SqlitePool::connect("sqlite::memory:")
        .await
        .unwrap();
    let first = request(pseudonymizer(5));
    let second = request(pseudonymizer(5));
    let first_future = scope(Arc::clone(&first), async {
        assert!(Arc::ptr_eq(&current().unwrap(), &first));
        pool.execute("SELECT 1").await.unwrap();
        tokio::task::yield_now().await;
        assert!(Arc::ptr_eq(&current().unwrap(), &first));
    });
    let second_future = scope(Arc::clone(&second), async {
        assert!(Arc::ptr_eq(&current().unwrap(), &second));
        pool.execute("SELECT 1").await.unwrap();
        pool.execute("SELECT 2").await.unwrap();
    });
    futures::future::join(first_future, second_future).await;
    assert!(current().is_none());
    assert_eq!(first.snapshot().query_count, 1);
    assert_eq!(second.snapshot().query_count, 2);
    assert!(first.snapshot().query_time_ns > 0);
    assert!(second.snapshot().pool_wait_ns > 0);
    pool.close().await;
}
