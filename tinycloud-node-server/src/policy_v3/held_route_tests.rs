//! Held-credential admission through the real `POST /policy/v3/delegations`
//! route. The harness never wires held config, so the held flag is off. A
//! held presentation must be refused by the route's flag gate, before the
//! verifier runs and before any nonce is spent.

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

on_both_backends!(held_presentation_is_refused_while_the_flag_is_off);
