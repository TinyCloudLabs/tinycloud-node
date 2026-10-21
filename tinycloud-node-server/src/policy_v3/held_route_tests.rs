//! Held-credential admission through the real `POST /policy/v3/delegations`
//! route. The default harness keeps the held flag off: a held presentation must
//! be refused by the flag gate before the verifier runs and before any nonce is
//! spent. `Harness::new_with_held` turns the flag on for the request-shape tests.

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
