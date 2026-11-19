//! TC-2492: a key's size and write time reach only the space's owner or a
//! caller whose cited delegations hold an unexpired `tinycloud.kv/get`
//! covering that key. Everyone else gets the key with both fields absent.

use super::*;
use rocket::http::Status;

/// `notes/open/a` (3 bytes) and `notes/hidden/b` (5 bytes), owner-written.
async fn fixture_with_values() -> Result<KvSyncFixture> {
    let fixture = KvSyncFixture::new().await?;
    fixture.owner_write("notes/open/a", Some(b"abc")).await?;
    fixture
        .owner_write("notes/hidden/b", Some(b"abcde"))
        .await?;
    Ok(fixture)
}

/// `(key, size, has updatedAt)` for each entry, plus the raw entries.
fn entries(reply: &SyncReply) -> Vec<(String, Option<u64>, bool)> {
    assert_eq!(reply.status, Status::Ok, "{}", reply.body);
    reply
        .json
        .as_array()
        .expect("entries array")
        .iter()
        .map(|entry| {
            let object = entry.as_object().expect("entry object");
            assert!(
                object.get("size").is_none_or(|size| size.is_u64()),
                "size is absent or a number: {entry}"
            );
            assert!(
                object
                    .get("updatedAt")
                    .is_none_or(|updated| updated.is_string()),
                "updatedAt is absent or a string: {entry}"
            );
            (
                object["key"].as_str().expect("key").to_owned(),
                object.get("size").and_then(serde_json::Value::as_u64),
                object.contains_key("updatedAt"),
            )
        })
        .collect()
}

async fn device_list(fixture: &KvSyncFixture, proofs: &[tinycloud_core::hash::Hash]) -> SyncReply {
    let header = fixture
        .device_invocation_in(&[(&fixture.space, "notes/", "tinycloud.kv/list")], proofs)
        .expect("device invocation");
    fixture
        .dispatch(header, &[("x-tinycloud-list-entries", "true")])
        .await
}

fn expected(visible: &[bool; 2]) -> Vec<(String, Option<u64>, bool)> {
    vec![
        (
            "notes/hidden/b".to_owned(),
            visible[0].then_some(5),
            visible[0],
        ),
        (
            "notes/open/a".to_owned(),
            visible[1].then_some(3),
            visible[1],
        ),
    ]
}

#[tokio::test]
async fn list_only_grant_sees_keys_without_size_or_time() -> Result<()> {
    let fixture = fixture_with_values().await?;
    let grant = fixture
        .device_grant("tc2492-vis-list-only", &["tinycloud.kv/list"])
        .await?;

    let reply = device_list(&fixture, &[grant]).await;
    assert_eq!(entries(&reply), expected(&[false, false]));
    assert!(
        !reply.body.contains("null"),
        "absent, not null: {}",
        reply.body
    );
    Ok(())
}

#[tokio::test]
async fn get_on_a_sub_path_reveals_only_keys_under_it() -> Result<()> {
    let fixture = fixture_with_values().await?;
    let grant = fixture
        .grant(
            "tc2492-vis-sub-path",
            &fixture.space.did().to_string(),
            &fixture.device_did(),
            &[
                ("notes/", "tinycloud.kv/list"),
                ("notes/", "tinycloud.kv/metadata"),
                ("notes/open/", "tinycloud.kv/get"),
            ],
            None,
            Some(whole_seconds_from_now(3600)),
            &[],
        )
        .await?;

    let reply = device_list(&fixture, &[grant]).await;
    assert_eq!(entries(&reply), expected(&[false, true]));

    // A head follows the same per-key rule.
    for (key, visible) in [("notes/open/a", true), ("notes/hidden/b", false)] {
        let header = fixture.device_invocation(&[(key, "tinycloud.kv/metadata")], grant)?;
        let response = fixture
            .client
            .post("/invoke")
            .header(rocket::http::Header::new("Authorization", header))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok, "{key}");
        assert!(response.headers().get_one("ETag").is_some(), "{key}");
        assert_eq!(
            response.headers().get_one("x-tinycloud-content-length"),
            visible.then_some(if key == "notes/open/a" { "3" } else { "5" }),
            "{key}"
        );
        assert_eq!(
            response.headers().get_one("Last-Modified").is_some(),
            visible,
            "{key}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn expired_get_reveals_nothing() -> Result<()> {
    let fixture = fixture_with_values().await?;
    let list = fixture
        .device_grant("tc2492-vis-expired-list", &["tinycloud.kv/list"])
        .await?;
    let expired_get = fixture
        .grant(
            "tc2492-vis-expired-get",
            &fixture.space.did().to_string(),
            &fixture.device_did(),
            &[("notes/", "tinycloud.kv/get")],
            Some(whole_seconds_from_now(-7200)),
            Some(whole_seconds_from_now(-3600)),
            &[],
        )
        .await?;

    // Held but expired: the list answers keys only.
    let reply = device_list(&fixture, &[list]).await;
    assert_eq!(entries(&reply), expected(&[false, false]));

    // Citing the expired get refuses the whole list, entries included.
    let reply = device_list(&fixture, &[list, expired_get]).await;
    assert_eq!(reply.status, Status::Unauthorized, "{}", reply.body);
    Ok(())
}

#[tokio::test]
async fn owner_sees_every_size_and_time() -> Result<()> {
    let fixture = fixture_with_values().await?;
    let header = fixture.owner_invocation(&[(
        fixture.kv_resource("notes/")?.to_string(),
        "tinycloud.kv/list",
    )])?;
    let reply = fixture
        .dispatch(header, &[("x-tinycloud-list-entries", "true")])
        .await;
    assert_eq!(entries(&reply), expected(&[true, true]));
    Ok(())
}
