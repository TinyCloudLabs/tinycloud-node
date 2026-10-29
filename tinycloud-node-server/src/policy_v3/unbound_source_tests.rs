//! TC-2242: a new Policy/v3 registration must bind its content source to one
//! share key. A registration without `encryptionKeyPath` (mutable or
//! immutable) or an immutable one without `encryptedSymmetricKeyDigestHex` is
//! refused at the registration route and stores nothing. A registration that
//! is already stored keeps validating, so links minted before the refusal
//! still open.

use super::test_harness::*;
use super::*;
use serde_json::json;

const KEY_PATH_REQUIRED: &str = "content-source-key-path-required";
const KEY_DIGEST_REQUIRED: &str = "content-source-key-digest-required";
const KV_GET: &str = "tinycloud.kv/get";
const DECRYPT: &str = "tinycloud.encryption/decrypt";

/// A node with named keys on, which a path-bound share key needs: the owner
/// of the policy is granted decrypt on the key itself. The ledger directory
/// lives as long as the harness.
pub(super) async fn boot(
    backend: Backend,
    test: &str,
) -> anyhow::Result<Option<(Harness, tempfile::TempDir)>> {
    let ledger = tempfile::tempdir()?;
    let path = ledger.path().join("deletion-ledger.jsonl");
    let named_keys = move |config: &mut crate::config::Config| {
        config.encryption_network.named_keys_v1 = true;
        config.encryption_network.deletion_ledger_path = Some(path);
    };
    Ok(
        Harness::new_with(backend, Shape::KeySession, test, named_keys)
            .await?
            .map(|h| (h, ledger)),
    )
}

/// The policy owner holds kv reads and decrypt on `key`.
pub(super) async fn grant_owner_key(h: &Harness, key: &str) -> anyhow::Result<()> {
    let grants = [
        (h.content_resource.to_string(), KV_GET),
        (h.content_resource.to_string(), "tinycloud.kv/metadata"),
        (key.to_owned(), DECRYPT),
    ];
    h.grant_owner_with(&grants, Window::until(now() + Duration::days(2)))
        .await?;
    Ok(())
}

/// A content source over the harness content. `key_path` and `digest` are left
/// out of the document when `None`.
fn content_source(
    h: &Harness,
    network: &str,
    mode: &str,
    key_path: Option<&str>,
    digest: Option<&str>,
) -> Value {
    let mut source = json!({
        "shareId": unique("share-tc-2242-"),
        "kvResource": h.content_resource.to_string(),
        "selector": "exact",
        "encryptionNetwork": network,
        "keyVersion": 1,
        "mode": mode,
    });
    let object = source.as_object_mut().unwrap();
    if mode == "immutable" {
        object.insert("initialCiphertextDigestHex".into(), json!("bb".repeat(32)));
    }
    if let Some(path) = key_path {
        object.insert("encryptionKeyPath".into(), json!(path));
    }
    if let Some(digest) = digest {
        object.insert("encryptedSymmetricKeyDigestHex".into(), json!(digest));
    }
    source
}

/// A path-bound source: its key is `share/<shareId>` on the default network.
pub(super) fn bound_source(h: &Harness, mode: &str, digest: Option<&str>) -> (Value, String) {
    let mut source = content_source(h, &h.default_network(), mode, None, digest);
    let key_path = format!("share/{}", source["shareId"].as_str().unwrap());
    source["encryptionKeyPath"] = json!(key_path);
    let leaf = format!("{}/{key_path}", h.default_network());
    (source, leaf)
}

/// What a challenge over the content and `decrypt` answers.
async fn challenge_decrypt(
    h: &Harness,
    policy: &Registered,
    decrypt: &str,
) -> anyhow::Result<(Status, String)> {
    let response = h
        .client
        .post("/policy/v3/challenges")
        .header(rocket::http::ContentType::JSON)
        .body(
            json!({
                "policyCid": policy.policy_cid,
                "recipientDid": h.holder.did(),
                "requestedCapabilities": [
                    {
                        "kind": "kv",
                        "resource": h.content_resource.to_string(),
                        "selector": "exact",
                        "actions": [KV_GET],
                    },
                    {"kind": "encryption", "resource": decrypt, "action": DECRYPT},
                ],
            })
            .to_string(),
        )
        .dispatch()
        .await;
    let status = response.status();
    Ok((status, response.into_string().await.unwrap_or_default()))
}

/// A refused registration answers `400` with its reason and stores nothing:
/// no registration, no root, no delegation, and the policy is unknown.
async fn assert_refused_and_unstored(
    h: &Harness,
    outcome: (Status, String, Registered),
    reason: &str,
    before: (u64, u64, u64),
) -> anyhow::Result<()> {
    let (status, body, registered) = outcome;
    assert_eq!(
        (status, body.as_str()),
        (Status::BadRequest, reason),
        "refusal"
    );
    assert_eq!(h.stored_rows().await?, before, "rows after {reason}");
    assert_eq!(
        h.challenge(&registered).await,
        (Status::NotFound, "policy-registration-missing".to_owned())
    );
    Ok(())
}

/// [a] a pathless network-wide decrypt, [b] a mutable source without a key
/// path, [c] an immutable source without the key digest: each is refused, and
/// nothing is stored.
async fn unbound_content_sources_are_refused_and_nothing_is_stored(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some((h, _ledger)) = boot(
        backend,
        "unbound_content_sources_are_refused_and_nothing_is_stored",
    )
    .await?
    else {
        return Ok(());
    };
    h.grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let (bound, leaf) = bound_source(&h, "immutable", None);
    grant_owner_key(&h, &leaf).await?;
    let before = h.stored_rows().await?;
    let digest = "aa".repeat(32);

    // [a] The whole network's decrypt, with the digest an immutable source
    // carries.
    let network = h.network.clone();
    let source = content_source(&h, &network, "immutable", None, Some(&digest));
    let outcome = h.register_source(policy_window(), source, &network).await?;
    assert_refused_and_unstored(&h, outcome, KEY_PATH_REQUIRED, before).await?;

    // [b] A mutable source without a key path.
    let source = content_source(&h, &network, "mutable", None, None);
    let outcome = h.register_source(policy_window(), source, &network).await?;
    assert_refused_and_unstored(&h, outcome, KEY_PATH_REQUIRED, before).await?;

    // [c] An immutable source bound to its key path, without the key digest.
    let outcome = h.register_source(policy_window(), bound, &leaf).await?;
    assert_refused_and_unstored(&h, outcome, KEY_DIGEST_REQUIRED, before).await
}
on_both_backends!(unbound_content_sources_are_refused_and_nothing_is_stored);

/// A registration stored before the refusal keeps opening: the same pathless
/// source is refused as a new registration, and once stored it answers a
/// challenge, mints, reads, passes the decrypt gate, and a replay of the
/// identical registration is still accepted.
async fn a_stored_legacy_registration_still_opens(backend: Backend) -> anyhow::Result<()> {
    let Some((h, _ledger)) = boot(backend, "a_stored_legacy_registration_still_opens").await?
    else {
        return Ok(());
    };
    h.grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let network = h.network.clone();
    let source = content_source(&h, &network, "immutable", None, Some(&"aa".repeat(32)));
    let (body, legacy) = h
        .registration_request(policy_window(), source, &network)
        .await?;

    let before = h.stored_rows().await?;
    let refused = h
        .client
        .post("/policy/v3/policies")
        .header(rocket::http::ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;
    assert_eq!(refused.status(), Status::BadRequest);
    assert_eq!(h.stored_rows().await?, before);

    h.store_registration(body.clone()).await?;
    assert_eq!(h.stored_rows().await?.0, before.0 + 1);

    let session = h.mint_ok(&legacy).await?;
    let (status, content) = h.read(&session).await?;
    assert_eq!(
        (status, text(&content)),
        (Status::Ok, "tc-1423-content".to_owned())
    );
    // The decrypt route admits the invocation (a policy refusal would be a
    // `403` naming the policy); it stops at the empty request body.
    let (status, answer) = h.decrypt(&session).await?;
    assert_ne!(status, Status::Unauthorized, "{answer}");
    assert!(!answer.contains("policy"), "{answer}");

    let replay = h
        .client
        .post("/policy/v3/policies")
        .header(rocket::http::ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;
    assert_eq!(replay.status(), Status::Ok);
    assert_eq!(h.stored_rows().await?.0, before.0 + 1);
    Ok(())
}
on_both_backends!(a_stored_legacy_registration_still_opens);

/// An exact path-bound registration (`share/<shareId>`, with its digest) is
/// stored, and the policy admits decrypt on that leaf only: not the network,
/// not a sibling key. The same share without its key path is refused.
async fn an_exact_path_bound_registration_succeeds_and_admits_only_its_leaf(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some((h, _ledger)) = boot(
        backend,
        "an_exact_path_bound_registration_succeeds_and_admits_only_its_leaf",
    )
    .await?
    else {
        return Ok(());
    };
    h.grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let before = h.stored_rows().await?;

    let (source, leaf) = bound_source(&h, "immutable", Some(&"aa".repeat(32)));
    grant_owner_key(&h, &leaf).await?;
    let (status, body, bound) = h.register_source(policy_window(), source, &leaf).await?;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(h.stored_rows().await?.0, before.0 + 1);

    assert_eq!(challenge_decrypt(&h, &bound, &leaf).await?.0, Status::Ok);
    for refused in [
        h.default_network(),
        format!("{}/share/other", h.default_network()),
    ] {
        let (status, body) = challenge_decrypt(&h, &bound, &refused).await?;
        assert!(
            status.class().is_client_error(),
            "{refused}: {status} {body}"
        );
    }

    // The key digest is only the immutable source's rule: a mutable source
    // bound to its key path registers without one.
    let (source, leaf) = bound_source(&h, "mutable", None);
    grant_owner_key(&h, &leaf).await?;
    let (status, body, _) = h.register_source(policy_window(), source, &leaf).await?;
    assert_eq!(status, Status::Ok, "{body}");

    // The same kind of source without a key path is the unbound shape.
    let rows = h.stored_rows().await?;
    let network = h.network.clone();
    let unbound = content_source(&h, &network, "mutable", None, None);
    let outcome = h
        .register_source(policy_window(), unbound, &network)
        .await?;
    assert_refused_and_unstored(&h, outcome, KEY_PATH_REQUIRED, rows).await
}
on_both_backends!(an_exact_path_bound_registration_succeeds_and_admits_only_its_leaf);

/// The refusal reads the content source only: a policy whose credential
/// requirement is not an email proof is refused for the same three shapes, and
/// its path-bound form registers.
async fn a_non_email_target_is_refused_the_same_way(backend: Backend) -> anyhow::Result<()> {
    let Some((h, _ledger)) = boot(backend, "a_non_email_target_is_refused_the_same_way").await?
    else {
        return Ok(());
    };
    h.grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let (bound, leaf) = bound_source(&h, "immutable", Some(&"aa".repeat(32)));
    let (no_digest, no_digest_leaf) = bound_source(&h, "immutable", None);
    grant_owner_key(&h, &leaf).await?;
    grant_owner_key(&h, &no_digest_leaf).await?;
    let before = h.stored_rows().await?;
    let network = h.network.clone();
    let requirement = h.non_email_requirement();

    let pathless = content_source(&h, &network, "immutable", None, Some(&"aa".repeat(32)));
    let mutable = content_source(&h, &network, "mutable", None, None);
    for (source, decrypt, reason) in [
        (pathless, network.as_str(), KEY_PATH_REQUIRED),
        (mutable, network.as_str(), KEY_PATH_REQUIRED),
        (no_digest, no_digest_leaf.as_str(), KEY_DIGEST_REQUIRED),
    ] {
        let outcome = h
            .register_source_for(policy_window(), source, decrypt, requirement.clone())
            .await?;
        assert_refused_and_unstored(&h, outcome, reason, before).await?;
    }

    let (status, body, _) = h
        .register_source_for(policy_window(), bound, &leaf, requirement)
        .await?;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(h.stored_rows().await?.0, before.0 + 1);
    Ok(())
}
on_both_backends!(a_non_email_target_is_refused_the_same_way);
