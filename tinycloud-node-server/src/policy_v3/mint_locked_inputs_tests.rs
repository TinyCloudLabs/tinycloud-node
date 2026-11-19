//! TC-2986 (F): a policy mint no longer re-runs credential admission, the
//! requested-capability check or the allow decision under its locks. It
//! shows their inputs unchanged instead: the challenge's fields, the
//! registration's bytes, and the roots' state. A change to any of them
//! after the checks and before the locks refuses the mint, and stores no
//! session.
//!
//! Each test holds the content space's write order, sends the mint, and
//! changes the input once the mint has passed its checks and waits for that
//! order. The challenge and registration changes are ones the checks accept,
//! so a change that landed before the checks would let the mint succeed and
//! fail the test; only the comparison under the locks refuses them.

use super::test_harness::*;
use super::*;
use std::future::Future;
use tinycloud_core::sea_orm::PaginatorTrait;

/// How long the write order stays held after the mint is sent: far longer
/// than the mint's checks before it, which take milliseconds.
const HOLD: std::time::Duration = std::time::Duration::from_millis(1500);

async fn registered(h: &Harness) -> anyhow::Result<Registered> {
    h.grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    h.register_ok(policy_window()).await
}

/// Mints for the holder while the content space's write order is held, and
/// applies `change` once the mint waits for it.
async fn mint_changed_while_waiting<F, Fut>(
    h: &Harness,
    policy: &Registered,
    change: F,
) -> anyhow::Result<Result<String, (Status, String)>>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let tinycloud = h.client.rocket().state::<crate::TinyCloud>().unwrap();
    let held = tinycloud
        .acquire_space_sequence_guards(std::slice::from_ref(&h.content_space))
        .await;
    let (minted, changed) = tokio::join!(h.mint(policy), async move {
        tokio::time::sleep(HOLD).await;
        let changed = change().await;
        drop(held);
        changed
    });
    changed?;
    minted
}

async fn sessions(h: &Harness) -> anyhow::Result<u64> {
    let runtime = h.client.rocket().state::<PolicyV3Runtime>().unwrap();
    Ok(policy_v3_session::Entity::find()
        .count(&runtime.conn)
        .await?)
}

/// The challenge's expiry moves later while the mint waits: still a live
/// challenge, but not the one the mint checked.
async fn a_challenge_changed_while_the_mint_waits_is_refused(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "a_challenge_changed_while_the_mint_waits_is_refused",
    )
    .await?
    else {
        return Ok(());
    };
    let policy = registered(&h).await?;
    let runtime = h.client.rocket().state::<PolicyV3Runtime>().unwrap();
    let minted = mint_changed_while_waiting(&h, &policy, || async {
        let changed = policy_v3_challenge::Entity::update_many()
            .col_expr(
                policy_v3_challenge::Column::ExpiresAt,
                Expr::value(format_time(now() + Duration::seconds(600))),
            )
            .filter(policy_v3_challenge::Column::PolicyCid.eq(policy.policy_cid.clone()))
            .exec(&runtime.conn)
            .await?;
        anyhow::ensure!(changed.rows_affected == 1, "one challenge");
        Ok(())
    })
    .await?;
    assert_eq!(
        minted.unwrap_err(),
        (Status::Unauthorized, "challenge-invalid".to_owned())
    );
    assert_eq!(sessions(&h).await?, 0);
    Ok(())
}
on_both_backends!(a_challenge_changed_while_the_mint_waits_is_refused);

/// The registration's attested enforcer binding is rewritten as the same
/// JSON with other whitespace while the mint waits: it still parses and
/// verifies, but the bytes the mint checked changed.
async fn a_registration_changed_while_the_mint_waits_is_refused(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "a_registration_changed_while_the_mint_waits_is_refused",
    )
    .await?
    else {
        return Ok(());
    };
    let policy = registered(&h).await?;
    let runtime = h.client.rocket().state::<PolicyV3Runtime>().unwrap();
    let minted = mint_changed_while_waiting(&h, &policy, || async {
        let registration = policy_v3_registration::Entity::find_by_id(policy.policy_cid.clone())
            .one(&runtime.conn)
            .await?
            .ok_or_else(|| anyhow::anyhow!("registration"))?;
        let binding: Value = serde_json::from_slice(&registration.attested_enforcer_binding_bytes)?;
        let rewritten = serde_json::to_vec_pretty(&binding)?;
        anyhow::ensure!(rewritten != registration.attested_enforcer_binding_bytes);
        policy_v3_registration::Entity::update_many()
            .col_expr(
                policy_v3_registration::Column::AttestedEnforcerBindingBytes,
                Expr::value(rewritten),
            )
            .filter(policy_v3_registration::Column::PolicyCid.eq(policy.policy_cid.clone()))
            .exec(&runtime.conn)
            .await?;
        Ok(())
    })
    .await?;
    assert_eq!(
        minted.unwrap_err(),
        (Status::Conflict, "policy-registration-changed".to_owned())
    );
    assert_eq!(sessions(&h).await?, 0);
    Ok(())
}
on_both_backends!(a_registration_changed_while_the_mint_waits_is_refused);

/// The policy root is revoked while the mint waits, after its signature and
/// state were checked: the mint is refused under the locks.
async fn a_root_revoked_while_the_mint_waits_is_refused(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "a_root_revoked_while_the_mint_waits_is_refused",
    )
    .await?
    else {
        return Ok(());
    };
    let policy = registered(&h).await?;
    let runtime = h.client.rocket().state::<PolicyV3Runtime>().unwrap();
    let root: tinycloud_auth::ipld_core::cid::Cid = policy.policy_root_cid.parse()?;
    let minted = mint_changed_while_waiting(&h, &policy, || async {
        // The row a generic revocation of the root stores.
        revocation::ActiveModel {
            id: Set(hash(policy.policy_root_cid.as_bytes())),
            revoker: Set(h.owner.did().to_owned()),
            revoked: Set(tinycloud_core::hash::Hash::from(root)),
            serialization: Set(b"tc-2986-revocation".to_vec()),
            revoked_at: Set(Some(now())),
        }
        .insert(&runtime.conn)
        .await?;
        Ok(())
    })
    .await?;
    assert_eq!(
        minted.unwrap_err(),
        (Status::Forbidden, "root-revoked".to_owned())
    );
    assert_eq!(sessions(&h).await?, 0);
    Ok(())
}
on_both_backends!(a_root_revoked_while_the_mint_waits_is_refused);

/// The registration is repointed at another registered, live policy root
/// while the mint waits: the root CIDs it checked are not the registration's
/// any more.
async fn a_registration_repointed_while_the_mint_waits_is_refused(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "a_registration_repointed_while_the_mint_waits_is_refused",
    )
    .await?
    else {
        return Ok(());
    };
    let policy = registered(&h).await?;
    let other = h.register_ok(policy_window()).await?;
    anyhow::ensure!(other.policy_root_cid != policy.policy_root_cid);
    let runtime = h.client.rocket().state::<PolicyV3Runtime>().unwrap();
    let minted = mint_changed_while_waiting(&h, &policy, || async {
        let changed = policy_v3_registration::Entity::update_many()
            .col_expr(
                policy_v3_registration::Column::PolicyRootCid,
                Expr::value(other.policy_root_cid.clone()),
            )
            .filter(policy_v3_registration::Column::PolicyCid.eq(policy.policy_cid.clone()))
            .exec(&runtime.conn)
            .await?;
        anyhow::ensure!(changed.rows_affected == 1, "one registration");
        Ok(())
    })
    .await?;
    assert_eq!(
        minted.unwrap_err(),
        (Status::Conflict, "policy-registration-changed".to_owned())
    );
    assert_eq!(sessions(&h).await?, 0);
    Ok(())
}
on_both_backends!(a_registration_repointed_while_the_mint_waits_is_refused);

/// A compact JWT with one signature character changed: the same header,
/// payload and facts, a signature that does not verify, and another CID.
fn forge_signature(jwt: &str) -> String {
    let at = jwt.rfind('.').unwrap() + 6;
    let mut bytes = jwt.as_bytes().to_vec();
    bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
    String::from_utf8(bytes).unwrap()
}

/// The policy root's stored bytes are replaced, while the mint waits, by the
/// same root under a forged signature. The signature is no longer checked
/// under the locks: the root bytes must still hash to the registration's
/// root CID, whose signature was checked before them (Bobbie's #596 review,
/// mutation M2b).
async fn root_bytes_replaced_while_the_mint_waits_are_refused(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "root_bytes_replaced_while_the_mint_waits_are_refused",
    )
    .await?
    else {
        return Ok(());
    };
    let policy = registered(&h).await?;
    let runtime = h.client.rocket().state::<PolicyV3Runtime>().unwrap();
    let minted = mint_changed_while_waiting(&h, &policy, || async {
        let row = policy_v3_root::Entity::find_by_id(policy.policy_root_cid.clone())
            .one(&runtime.conn)
            .await?
            .ok_or_else(|| anyhow::anyhow!("root row"))?;
        let forged = forge_signature(std::str::from_utf8(&row.authorization_bytes)?);
        let decoded = decode_delegation(&forged).map_err(|(_, error)| anyhow::anyhow!(error))?;
        anyhow::ensure!(decoded.serialized_bytes() == forged.as_bytes());
        anyhow::ensure!(decoded.content_hash().to_cid(0x55).to_string() != policy.policy_root_cid);
        let changed = policy_v3_root::Entity::update_many()
            .col_expr(
                policy_v3_root::Column::AuthorizationBytes,
                Expr::value(forged.into_bytes()),
            )
            .filter(policy_v3_root::Column::RootCid.eq(policy.policy_root_cid.clone()))
            .exec(&runtime.conn)
            .await?;
        anyhow::ensure!(changed.rows_affected == 1, "one root");
        Ok(())
    })
    .await?;
    assert_eq!(
        minted.unwrap_err(),
        (
            Status::Forbidden,
            "policy-root-projection-mismatch".to_owned()
        )
    );
    assert_eq!(sessions(&h).await?, 0);
    Ok(())
}
on_both_backends!(root_bytes_replaced_while_the_mint_waits_are_refused);
