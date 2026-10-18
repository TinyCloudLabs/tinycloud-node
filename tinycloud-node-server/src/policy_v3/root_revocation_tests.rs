//! TC-1423 (design §15): who can revoke a Policy/v3 root, and what follows.
//!
//! The owner of the content space revokes any policy root issued in it over
//! the generic `POST /revoke` (SIWE or UCAN), as does a holder of an
//! owner-granted revoke control. The JSON `RootRevocation/v1` route stays
//! limited to the root's own signer and, for the enforcement root, the
//! enforcer. Everyone else is refused on both routes.

use super::test_harness::*;
use super::*;
use serde_json::json;

const ROOT_REVOKED: &str = "root-revoked";
const POLICY_AUTHORITY: &str = "policy-authority";
const POLICY_ENFORCEMENT: &str = "policy-enforcement";

/// A registered policy with an admitted session that reads, and a re-shared
/// child that reads.
/// The generic route's refusal of a principal that may not revoke.
const UNAUTHORIZED_REVOKER: &str = "Unauthorized Revoker";

struct Admitted {
    policy: Registered,
    session: String,
    reader: Signer,
    child: tinycloud_auth::ipld_core::cid::Cid,
}

async fn admitted(h: &Harness) -> anyhow::Result<Admitted> {
    h.grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let policy = h.register_ok(policy_window()).await?;
    let session = h.mint_ok(&policy).await?;
    let (status, _) = h.read(&session).await?;
    anyhow::ensure!(status == Status::Ok, "read before revoke: {status}");
    let (status, body, reader, child) = h.reshare(&session).await?;
    anyhow::ensure!(status == Status::Ok, "re-share: {body}");
    let child = child.ok_or_else(|| anyhow::anyhow!("re-share cid"))?;
    anyhow::ensure!(h.read_as(&reader, child).await?.0 == Status::Ok);
    Ok(Admitted {
        policy,
        session,
        reader,
        child,
    })
}

/// After a generic revocation of the policy root: the admitted session,
/// its decrypt and its re-shared child stop with `root-revoked`, new
/// sessions are refused, and the status routes report it.
async fn assert_root_revoked_cascade(h: &Harness, admitted: &Admitted) -> anyhow::Result<()> {
    let (status, body) = h.read(&admitted.session).await?;
    assert_eq!(
        (status, text(&body).as_str()),
        (Status::Forbidden, ROOT_REVOKED)
    );
    // The decrypt route authorizes the invocation chain before the policy
    // check, so a revoked root surfaces as the core ancestor revocation.
    let (status, body) = h.decrypt(&admitted.session).await?;
    assert_eq!(status, Status::Unauthorized, "{body}");
    assert!(body.starts_with("delegation-ancestor-revoked"), "{body}");
    assert_eq!(
        h.read_as(&admitted.reader, admitted.child).await?,
        (Status::Forbidden, ROOT_REVOKED.to_owned())
    );
    assert_eq!(h.challenge(&admitted.policy).await.0, Status::Forbidden);
    assert_eq!(
        h.mint(&admitted.policy).await?.unwrap_err().0,
        Status::Forbidden
    );
    // The signer of the root sees it revoked.
    assert_eq!(
        h.delegation_status(&h.owner, &admitted.policy.policy_root_cid)
            .await?["status"],
        json!("revoked")
    );
    // The public status reports `revoked` over the last (active)
    // checkpoint, and renewal is refused.
    let status = h.root_status(&admitted.policy.policy_root_cid).await;
    assert_eq!(status["state"], json!("revoked"), "{status}");
    assert_eq!(status["checkpoint"]["state"], json!("active"), "{status}");
    assert_eq!(
        h.renew_status(&admitted.policy.policy_root_cid).await,
        (Status::Conflict, ROOT_REVOKED.to_owned())
    );
    Ok(())
}

/// The root is untouched: still active on both status routes, and the
/// admitted session still reads.
async fn assert_root_live(h: &Harness, admitted: &Admitted) -> anyhow::Result<()> {
    assert_eq!(h.read(&admitted.session).await?.0, Status::Ok);
    let status = h.root_status(&admitted.policy.policy_root_cid).await;
    assert_eq!(status["state"], json!("active"), "{status}");
    Ok(())
}

/// [O-1] The wallet that owns the space (did:pkh) revokes the agent-signed
/// root over the generic route with SIWE.
async fn the_space_owner_wallet_revokes_an_agent_signed_root(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::PkhSession,
        "the_space_owner_wallet_revokes_an_agent_signed_root",
    )
    .await?
    else {
        return Ok(());
    };
    let admitted = admitted(&h).await?;
    assert_no_hook_ticket(&h, &admitted, "Unauthorized Action").await?;
    h.revoke(&h.space_owner, &admitted.policy.policy_root_cid)
        .await?;
    assert_root_revoked_cascade(&h, &admitted).await?;
    // Now the chain check refuses it first.
    assert_no_hook_ticket(&h, &admitted, "delegation-ancestor-revoked").await
}

/// Policy sessions hold only kv and decrypt, so a hook ticket over one is
/// refused (401, with the cause `refusal` names): there is no hook stream
/// to close after a root revocation.
async fn assert_no_hook_ticket(
    h: &Harness,
    admitted: &Admitted,
    refusal: &str,
) -> anyhow::Result<()> {
    let (status, body) = h
        .hook_ticket(&[session_cid(&admitted.session)?.to_string()])
        .await?;
    assert_eq!(status, Status::Unauthorized, "{body}");
    assert!(body.starts_with(refusal), "{body}");
    Ok(())
}
on_both_backends!(the_space_owner_wallet_revokes_an_agent_signed_root);

/// [O-2] A did:key space owner revokes the agent-signed root over the
/// generic route (UCAN); the JSON route still refuses it.
async fn a_key_space_owner_revokes_over_the_generic_route_only(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "a_key_space_owner_revokes_over_the_generic_route_only",
    )
    .await?
    else {
        return Ok(());
    };
    let admitted = admitted(&h).await?;
    let (status, body) = h
        .revoke_root_json(
            &h.space_owner,
            &admitted.policy.policy_root_cid,
            POLICY_AUTHORITY,
        )
        .await?;
    assert_eq!(
        (status, body.as_str()),
        (Status::Forbidden, "root-revocation-issuer-invalid")
    );
    assert_root_live(&h, &admitted).await?;
    h.revoke(&h.space_owner, &admitted.policy.policy_root_cid)
        .await?;
    assert_root_revoked_cascade(&h, &admitted).await
}
on_both_backends!(a_key_space_owner_revokes_over_the_generic_route_only);

/// [O-3][O-4][O-5] An unrelated key, another agent session of the same
/// wallet, and the recipient are refused on both routes; nothing changes.
async fn others_cannot_revoke_a_policy_root(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::PkhSession,
        "others_cannot_revoke_a_policy_root",
    )
    .await?
    else {
        return Ok(());
    };
    let admitted = admitted(&h).await?;
    let other_agent = Signer::key();
    h.import(h.space_owner.delegate(
        other_agent.did(),
        &h.owner_grants(),
        Window::until(now() + Duration::days(2)),
        &[],
    )?)
    .await?;
    let stranger = Signer::key();
    let root = admitted.policy.policy_root_cid.clone();
    for (label, signer) in [
        ("unrelated principal", &stranger),
        ("another agent of the wallet", &other_agent),
        ("recipient", &h.holder),
    ] {
        let (status, body) = h.post_revoke(signer.revoke(&root)?).await;
        assert_eq!(
            (status, body.as_str()),
            (Status::Forbidden, UNAUTHORIZED_REVOKER),
            "{label} generic"
        );
        let (status, body) = h.revoke_root_json(signer, &root, POLICY_AUTHORITY).await?;
        assert_eq!(status, Status::Forbidden, "{label} JSON: {body}");
        assert_root_live(&h, &admitted).await?;
    }
    assert_eq!(
        h.delegation_status(&h.owner, &root).await?["status"],
        json!("active")
    );
    Ok(())
}
on_both_backends!(others_cannot_revoke_a_policy_root);

/// [O-6] A key holding the wallet's revoke control over the space's
/// delegations and the encryption network revokes a decrypt-bearing root;
/// the same control without the network row cannot.
async fn a_revoke_control_naming_the_network_revokes_a_policy_root(
    backend: Backend,
) -> anyhow::Result<()> {
    for with_network in [false, true] {
        let Some(h) = Harness::new(
            backend,
            Shape::PkhSession,
            "a_revoke_control_naming_the_network_revokes_a_policy_root",
        )
        .await?
        else {
            return Ok(());
        };
        let admitted = admitted(&h).await?;
        let device = Signer::key();
        let delegation_root = h
            .content_space
            .clone()
            .to_resource("delegation".parse()?, None, None, None)
            .to_string();
        let mut rows = vec![(delegation_root, "tinycloud.delegation/revoke")];
        if with_network {
            rows.push((h.network.clone(), "tinycloud.delegation/revoke"));
        }
        let control = h
            .import(h.space_owner.delegate(
                device.did(),
                &rows,
                Window::until(now() + Duration::hours(1)),
                &[],
            )?)
            .await?;
        let (status, body) = h
            .post_revoke(
                device.revoke_citing(&admitted.policy.policy_root_cid, &[control.parse()?])?,
            )
            .await;
        if with_network {
            assert_eq!(status, Status::Ok, "{body}");
            assert_root_revoked_cascade(&h, &admitted).await?;
        } else {
            assert_eq!(
                (status, body.as_str()),
                (Status::Forbidden, UNAUTHORIZED_REVOKER),
                "space-only control"
            );
            assert_root_live(&h, &admitted).await?;
        }
    }
    Ok(())
}
on_both_backends!(a_revoke_control_naming_the_network_revokes_a_policy_root);

/// [O-7] The root's signer revokes over JSON, and the status the released
/// SDK parses stays consistent (`state` equals the checkpoint's). The
/// enforcer revokes the enforcement root over JSON but not the policy root.
async fn the_json_route_keeps_its_signer_and_enforcer_rules(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::PkhSession,
        "the_json_route_keeps_its_signer_and_enforcer_rules",
    )
    .await?
    else {
        return Ok(());
    };
    let first = admitted(&h).await?;
    // The enforcer is the delegatee of the enforcement root. The generic
    // route refuses a delegatee on either root.
    for root in [
        &first.policy.policy_root_cid,
        &first.policy.enforcement_root_cid,
    ] {
        let (status, body) = h.post_revoke(h.enforcer.revoke(root)?).await;
        assert_eq!(
            (status, body.as_str()),
            (Status::Forbidden, UNAUTHORIZED_REVOKER)
        );
    }
    assert_root_live(&h, &first).await?;
    let (status, body) = h
        .revoke_root_json(&h.enforcer, &first.policy.policy_root_cid, POLICY_AUTHORITY)
        .await?;
    assert_eq!(
        status,
        Status::Forbidden,
        "enforcer on the policy root: {body}"
    );
    let (status, body) = h
        .revoke_root_json(
            &h.enforcer,
            &first.policy.enforcement_root_cid,
            POLICY_ENFORCEMENT,
        )
        .await?;
    assert_eq!(
        status,
        Status::Ok,
        "enforcer on the enforcement root: {body}"
    );
    let status = h.root_status(&first.policy.enforcement_root_cid).await;
    assert_eq!(status["state"], json!("revoked"), "{status}");
    assert_eq!(status["state"], status["checkpoint"]["state"], "{status}");

    let policy = h.register_ok(policy_window()).await?;
    let (status, body) = h
        .revoke_root_json(&h.owner, &policy.policy_root_cid, POLICY_AUTHORITY)
        .await?;
    assert_eq!(status, Status::Ok, "signer: {body}");
    let status = h.root_status(&policy.policy_root_cid).await;
    assert_eq!(status["state"], json!("revoked"), "{status}");
    assert_eq!(status["state"], status["checkpoint"]["state"], "{status}");
    Ok(())
}
on_both_backends!(the_json_route_keeps_its_signer_and_enforcer_rules);
