//! Held-credential admission through the real `POST /policy/v3/delegations`
//! route. The default harness keeps the held flag off: a held presentation must
//! be refused by the flag gate before the verifier runs and before any nonce is
//! spent. `Harness::new_with_held` turns the flag on for the request-shape tests.

use super::held_fixtures::*;
use super::test_harness::*;
use super::*;

async fn held_presentation_is_refused_while_the_flag_is_off(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "held_presentation_is_refused_while_the_flag_is_off",
    )
    .await?
    else {
        return Ok(());
    };
    h.grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let policy = h.register_ok(policy_window()).await?;
    let (status, body) = h.mint_held_presentation(&policy).await?;
    assert_eq!(status, Status::Forbidden, "{body}");
    assert!(body.contains("held-credentials-disabled"), "{body}");
    Ok(())
}

async fn held_request_with_a_credential_field_is_refused_by_the_shape_gate(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::new_with_held(
        backend,
        Shape::KeySession,
        "held_request_with_a_credential_field_is_refused_by_the_shape_gate",
        true,
    )
    .await?
    else {
        return Ok(());
    };
    h.grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let policy = h.register_ok(policy_window()).await?;
    let (status, body) = h.mint_held_with_credential(&policy).await?;
    assert_eq!(status, Status::BadRequest, "{body}");
    assert!(
        body.contains("credential-admission-request-invalid"),
        "{body}"
    );
    Ok(())
}

on_both_backends!(held_request_with_a_credential_field_is_refused_by_the_shape_gate);

on_both_backends!(held_presentation_is_refused_while_the_flag_is_off);

async fn held_mint_admits_once_and_returns_an_authorization(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::new_with_held(
        backend,
        Shape::KeySession,
        "held_mint_admits_once_and_returns_an_authorization",
        true,
    )
    .await?
    else {
        return Ok(());
    };
    h.grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let account = HeldAccount::new()?;
    let (account_cid, space) = import_account_authorization(&h, &account).await?;
    let policy = register_held(&h).await?;
    let presentation = outstanding_presentation(&h, &account, 86_400).await?;
    let requested = format_time(now() + Duration::seconds(3600));
    let (status, body) =
        mint_held(&h, &policy, &presentation, &account_cid, &space, &requested).await?;
    assert_eq!(status, Status::Ok, "{body}");
    let json: Value = serde_json::from_str(&body)?;
    assert!(
        json["authorization"]
            .as_str()
            .is_some_and(|token| token.split('.').count() == 3),
        "{body}"
    );
    Ok(())
}

async fn held_nonce_cannot_be_replayed_with_a_fresh_challenge(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::new_with_held(
        backend,
        Shape::KeySession,
        "held_nonce_cannot_be_replayed_with_a_fresh_challenge",
        true,
    )
    .await?
    else {
        return Ok(());
    };
    h.grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let account = HeldAccount::new()?;
    let (account_cid, space) = import_account_authorization(&h, &account).await?;
    let policy = register_held(&h).await?;
    let presentation = outstanding_presentation(&h, &account, 86_400).await?;
    let requested = format_time(now() + Duration::seconds(3600));
    let (first, body) =
        mint_held(&h, &policy, &presentation, &account_cid, &space, &requested).await?;
    assert_eq!(first, Status::Ok, "{body}");
    // Same SIWE nonce, new challenge: the nonce is the single-use key.
    let (second, body) =
        mint_held(&h, &policy, &presentation, &account_cid, &space, &requested).await?;
    assert_eq!(second, Status::Forbidden, "{body}");
    assert!(body.contains("nonce-replayed"), "{body}");
    Ok(())
}

async fn held_session_expiry_is_clamped_to_the_credential_expiry(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::new_with_held(
        backend,
        Shape::KeySession,
        "held_session_expiry_is_clamped_to_the_credential_expiry",
        true,
    )
    .await?
    else {
        return Ok(());
    };
    h.grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let account = HeldAccount::new()?;
    let (account_cid, space) = import_account_authorization(&h, &account).await?;
    let policy = register_held(&h).await?;
    let issued_at = now().unix_timestamp();
    // The credential lives 120 seconds; the request asks for an hour.
    let presentation = outstanding_presentation(&h, &account, 120).await?;
    let requested = format_time(now() + Duration::seconds(3600));
    let (status, body) =
        mint_held(&h, &policy, &presentation, &account_cid, &space, &requested).await?;
    assert_eq!(status, Status::Ok, "{body}");
    let token = serde_json::from_str::<Value>(&body)?["authorization"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing authorization: {body}"))?
        .to_owned();
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("malformed authorization"))?;
    let claims: Value =
        serde_json::from_slice(&base64::decode_config(payload, base64::URL_SAFE_NO_PAD)?)?;
    let exp = claims["exp"]
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("missing exp: {claims}"))?;
    assert!(
        exp - issued_at <= 130,
        "session exp {exp} exceeds the 120s credential lifetime from {issued_at}"
    );
    Ok(())
}

async fn held_presentation_with_the_required_vct_is_admitted(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::new_with_held(
        backend,
        Shape::KeySession,
        "held_presentation_with_the_required_vct_is_admitted",
        true,
    )
    .await?
    else {
        return Ok(());
    };
    h.grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let account = HeldAccount::new()?;
    let (account_cid, space) = import_account_authorization(&h, &account).await?;
    let policy = register_held(&h).await?;
    let presentation = outstanding_presentation_with_vct(&h, &account, 86_400, HELD_VCT).await?;
    let requested = format_time(now() + Duration::seconds(3600));
    let (status, body) =
        mint_held(&h, &policy, &presentation, &account_cid, &space, &requested).await?;
    assert_eq!(status, Status::Ok, "{body}");
    Ok(())
}

async fn held_presentation_with_a_mismatched_vct_is_refused(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::new_with_held(
        backend,
        Shape::KeySession,
        "held_presentation_with_a_mismatched_vct_is_refused",
        true,
    )
    .await?
    else {
        return Ok(());
    };
    h.grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let account = HeldAccount::new()?;
    let (account_cid, space) = import_account_authorization(&h, &account).await?;
    let policy = register_held(&h).await?;
    // Issuer-signed with a `vct` other than the held credential type. The
    // signature and disclosure digests stay valid, so the refusal comes from
    // `held_email::verify` (`vct != VCT`), not from the signature checks.
    let presentation =
        outstanding_presentation_with_vct(&h, &account, 86_400, "opencredentials.phone/v1").await?;
    let requested = format_time(now() + Duration::seconds(3600));
    let (status, body) =
        mint_held(&h, &policy, &presentation, &account_cid, &space, &requested).await?;
    assert_eq!(status, Status::Forbidden, "{body}");
    assert!(body.contains("profile-mismatch"), "{body}");
    Ok(())
}

on_both_backends!(held_mint_admits_once_and_returns_an_authorization);

on_both_backends!(held_nonce_cannot_be_replayed_with_a_fresh_challenge);

on_both_backends!(held_session_expiry_is_clamped_to_the_credential_expiry);

on_both_backends!(held_presentation_with_the_required_vct_is_admitted);

on_both_backends!(held_presentation_with_a_mismatched_vct_is_refused);
