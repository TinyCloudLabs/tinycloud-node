use crate::{
    authorization::AuthHeaderGetter,
    hooks::{
        hook_scope_path, matches_scope, normalize_path_prefix, HookRuntime, HookSubscription,
        HookTicketClaims, HookTicketRequest, HookTicketResponse,
    },
    TinyCloud,
};
use rocket::{
    get, post,
    http::Status,
    response::stream::{Event, EventStream},
    serde::json::Json,
    State,
};
use std::time::Duration;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_core::{
    hash::Hash,
    models::delegation,
    types::Resource,
    sea_orm::{ColumnTrait, EntityTrait, QueryFilter},
    util::InvocationInfo,
};

#[post("/hooks/tickets", format = "json", data = "<request>")]
pub async fn create_hook_ticket(
    invocation: AuthHeaderGetter<InvocationInfo>,
    request: Json<HookTicketRequest>,
    hooks: &State<HookRuntime>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<HookTicketResponse>, (Status, String)> {
    mint_hook_ticket(&invocation.0.0, request.into_inner(), hooks.inner(), tinycloud.inner())
        .await
        .map(Json)
}

pub async fn mint_hook_ticket(
    invocation: &InvocationInfo,
    mut request: HookTicketRequest,
    hooks: &HookRuntime,
    tinycloud: &TinyCloud,
) -> Result<HookTicketResponse, (Status, String)> {
    if request.subscriptions.is_empty() {
        return Err((Status::BadRequest, "at least one subscription is required".to_string()));
    }
    if request.subscriptions.len() > hooks.config().max_scopes_per_ticket {
        return Err((Status::BadRequest, "too many requested hook scopes".to_string()));
    }

    for subscription in &mut request.subscriptions {
        subscription.path_prefix = normalize_path_prefix(subscription.path_prefix.take());
        validate_subscription(subscription)?;
        if !is_subscription_authorized(&invocation, subscription) {
            return Err((Status::Forbidden, "requested hook scope is not authorized".to_string()));
        }
    }

    let now = OffsetDateTime::now_utc();
    let invocation_exp = invocation_expiry(invocation)?;
    let parent_exp = find_parent_expiry(invocation, tinycloud)
        .await?
        .unwrap_or(invocation_exp);
    let requested_ttl = request
        .ttl_seconds
        .unwrap_or(hooks.config().max_ticket_ttl_seconds)
        .min(hooks.config().max_ticket_ttl_seconds) as i64;

    let exp = (now.unix_timestamp() + requested_ttl)
        .min(invocation_exp)
        .min(parent_exp);

    if exp <= now.unix_timestamp() {
        return Err((Status::Unauthorized, "hook ticket expired immediately".to_string()));
    }

    let claims = HookTicketClaims {
        v: 1,
        sub: invocation.invoker.clone(),
        scopes: request.subscriptions,
        iat: now.unix_timestamp(),
        exp,
        parent_exp,
    };
    let ticket = hooks
        .sign_ticket(&claims)
        .map_err(|e| (Status::InternalServerError, e))?;
    let expires_at = OffsetDateTime::from_unix_timestamp(exp)
        .map_err(|e| (Status::InternalServerError, e.to_string()))?
        .format(&Rfc3339)
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;

    Ok(HookTicketResponse { ticket, expires_at })
}

#[get("/hooks/events?<ticket>")]
pub async fn hook_events<'r>(
    ticket: &'r str,
    hooks: &'r State<HookRuntime>,
) -> Result<EventStream![Event + 'r], (Status, String)> {
    let claims = hooks
        .verify_ticket(ticket)
        .map_err(|e| (Status::Unauthorized, e))?;
    let lease = hooks
        .try_acquire_stream()
        .map_err(|e| (Status::TooManyRequests, e))?;

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let deadline = claims
        .exp
        .min(claims.parent_exp)
        .min(now + hooks.config().max_ticket_ttl_seconds as i64);

    if deadline <= now {
        return Err((Status::Unauthorized, "hook ticket expired".to_string()));
    }

    let mut receiver = hooks.bus().subscribe();
    let sleep_duration = Duration::from_secs((deadline - now) as u64);

    Ok(EventStream! {
        let _lease = lease;
        let mut deadline_sleep = rocket::tokio::time::sleep(sleep_duration);
        rocket::tokio::pin!(deadline_sleep);

        loop {
            rocket::tokio::select! {
                _ = &mut deadline_sleep => {
                    break;
                }
                message = receiver.recv() => {
                    match message {
                        Ok(event) => {
                            if claims.scopes.iter().any(|scope| matches_scope(&event, scope)) {
                                yield Event::json(&event)
                                    .id(event.id.clone())
                                    .event("write");
                            }
                        }
                        Err(rocket::tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            continue;
                        }
                        Err(rocket::tokio::sync::broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
            }
        }
    }
    .heartbeat(Duration::from_secs(30)))
}

fn validate_subscription(subscription: &HookSubscription) -> Result<(), (Status, String)> {
    if subscription.service.as_str() != "kv" {
        return Err((Status::BadRequest, "Phase 1 only supports kv hooks".to_string()));
    }

    let expected_prefix = "tinycloud.kv/";

    if subscription
        .abilities
        .iter()
        .any(|ability| !ability.starts_with(expected_prefix))
    {
        return Err((Status::BadRequest, "hook ability filter does not match service".to_string()));
    }

    Ok(())
}

fn is_subscription_authorized(invocation: &InvocationInfo, subscription: &HookSubscription) -> bool {
    let requested_scope = hook_scope_path(
        &subscription.service,
        subscription.path_prefix.as_deref(),
    );

    invocation.capabilities.iter().any(|capability| match (&capability.resource, capability.ability.as_ref().as_ref()) {
        (Resource::TinyCloud(resource), "tinycloud.hooks/subscribe")
            if resource.service().as_str() == "hooks"
                && resource.space().to_string() == subscription.space =>
        {
            match resource.path() {
                Some(path) => scope_extends(&requested_scope, &path.to_string()),
                None => true,
            }
        }
        _ => false,
    })
}

fn scope_extends(requested_scope: &str, authorized_scope: &str) -> bool {
    requested_scope == authorized_scope
        || requested_scope.starts_with(&format!("{authorized_scope}/"))
}

fn invocation_expiry(invocation: &InvocationInfo) -> Result<i64, (Status, String)> {
    Ok(invocation.invocation.payload().expiration.as_seconds().floor() as i64)
}

async fn find_parent_expiry(
    invocation: &InvocationInfo,
    tinycloud: &TinyCloud,
) -> Result<Option<i64>, (Status, String)> {
    if invocation.parents.is_empty() {
        return Ok(None);
    }

    let tx = tinycloud
        .readable()
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;

    let parent_ids: Vec<Hash> = invocation.parents.iter().map(|cid| Hash::from(*cid)).collect();

    let expiries = delegation::Entity::find()
        .filter(delegation::Column::Id.is_in(parent_ids))
        .all(&tx)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;

    Ok(expiries
        .into_iter()
        .filter_map(|delegation| delegation.expiry.map(|expiry| expiry.unix_timestamp()))
        .min())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::HooksConfig,
        hooks::HookRuntime,
        storage::file_system::FileSystemConfig as NodeFileSystemConfig,
        TinyCloud,
    };
    use anyhow::Result;
    use rocket::http::Status;
    use tempfile::TempDir;
    use tinycloud_auth::{
        authorization::{make_invocation, InvocationOptions},
        ipld_core::cid::Cid,
        multihash_codetable::{Code, MultihashDigest},
        resolver::DID_METHODS,
        resource::{Path, ResourceId, Service, SpaceId},
        siwe_recap::Ability,
        ssi::{dids::DIDBuf, jwk::JWK},
    };
    use tinycloud_core::{
        keys::StaticSecret,
        sea_orm::{ConnectOptions, Database},
        storage::StorageConfig as _,
        storage::either::Either,
        util::InvocationInfo as CoreInvocationInfo,
    };

    fn test_hook_runtime() -> HookRuntime {
        HookRuntime::new(HooksConfig::default(), [7u8; 32])
    }

    async fn test_tinycloud() -> Result<TinyCloud> {
        let tempdir = TempDir::new()?;
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string())).await?;
        let storage = NodeFileSystemConfig::new(tempdir.path()).open().await?;
        let _persisted = tempdir.into_path();
        Ok(
            TinyCloud::new(
                db,
                Either::B(storage),
                StaticSecret::new(vec![0u8; 32]).unwrap(),
            )
            .await?,
        )
    }

    fn test_invocation() -> Result<(CoreInvocationInfo, String)> {
        let jwk = JWK::generate_ed25519()?;
        let mut verification_method = DID_METHODS.generate(&jwk, "key")?.to_string();
        let fragment = verification_method
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("missing verification method fragment"))?
            .1
            .to_string();
        verification_method.push('#');
        verification_method.push_str(&fragment);

        let did: DIDBuf = verification_method
            .split('#')
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing did"))?
            .parse()?;
        let space = SpaceId::new(did, "alpha".parse()?);
        let space_string = space.to_string();
        let hook_resource: ResourceId = space
            .clone()
            .to_resource(
                "hooks".parse::<Service>()?,
                Some("kv/documents".parse::<Path>()?),
                None,
                None,
            );

        let delegation = Cid::new_v1(0x55, Code::Blake3_256.digest(b"delegation"));
        let invocation = make_invocation(
            vec![(hook_resource, vec!["tinycloud.hooks/subscribe".parse::<Ability>()?])],
            &delegation,
            &jwk,
            &verification_method,
            4_102_444_800.0,
            InvocationOptions::default(),
        )?;

        Ok((CoreInvocationInfo::try_from(invocation)?, space_string))
    }

    #[tokio::test]
    async fn mints_ticket_for_authorized_scope() -> Result<()> {
        let tinycloud = test_tinycloud().await?;
        let hooks = test_hook_runtime();
        let (invocation, space) = test_invocation()?;
        let request = HookTicketRequest {
            subscriptions: vec![HookSubscription {
                space,
                service: "kv".to_string(),
                path_prefix: Some("documents".to_string()),
                abilities: vec!["tinycloud.kv/put".to_string()],
            }],
            ttl_seconds: Some(60),
        };

        let response = mint_hook_ticket(&invocation, request, &hooks, &tinycloud)
            .await
            .expect("ticket");
        let claims = hooks.verify_ticket(&response.ticket).unwrap();
        assert_eq!(claims.sub, invocation.invoker);
        assert_eq!(claims.scopes.len(), 1);
        assert_eq!(claims.scopes[0].service, "kv");
        assert_eq!(claims.scopes[0].path_prefix.as_deref(), Some("documents"));
        Ok(())
    }

    #[tokio::test]
    async fn rejects_partially_authorized_ticket_requests() -> Result<()> {
        let tinycloud = test_tinycloud().await?;
        let hooks = test_hook_runtime();
        let (invocation, space) = test_invocation()?;

        let request = HookTicketRequest {
            subscriptions: vec![
                HookSubscription {
                    space: space.clone(),
                    service: "kv".to_string(),
                    path_prefix: Some("documents".to_string()),
                    abilities: vec!["tinycloud.kv/put".to_string()],
                },
                HookSubscription {
                    space,
                    service: "kv".to_string(),
                    path_prefix: Some("private".to_string()),
                    abilities: vec!["tinycloud.kv/put".to_string()],
                },
            ],
            ttl_seconds: Some(60),
        };

        let err = mint_hook_ticket(&invocation, request, &hooks, &tinycloud)
            .await
            .expect_err("should reject mixed authorization");
        assert_eq!(err.0, Status::Forbidden);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_wrong_space_subscription() -> Result<()> {
        let tinycloud = test_tinycloud().await?;
        let hooks = test_hook_runtime();
        let (invocation, _space) = test_invocation()?;
        let request = HookTicketRequest {
            subscriptions: vec![HookSubscription {
                space: "tinycloud:other-space".to_string(),
                service: "kv".to_string(),
                path_prefix: Some("documents".to_string()),
                abilities: vec!["tinycloud.kv/put".to_string()],
            }],
            ttl_seconds: Some(60),
        };

        let err = mint_hook_ticket(&invocation, request, &hooks, &tinycloud)
            .await
            .expect_err("should reject wrong space");
        assert_eq!(err.0, Status::Forbidden);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_non_kv_phase1_subscriptions() {
        let err = validate_subscription(&HookSubscription {
            space: "tinycloud:space".to_string(),
            service: "sql".to_string(),
            path_prefix: Some("main".to_string()),
            abilities: vec!["tinycloud.sql/execute".to_string()],
        })
        .expect_err("phase 1 must reject sql subscriptions");

        assert_eq!(err.0, Status::BadRequest);
    }
}
