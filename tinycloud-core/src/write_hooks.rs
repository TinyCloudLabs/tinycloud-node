use crate::hash::Blake3Hasher;
use crate::models::hook_subscription;
use crate::models::{abilities, delegation, invocation};
use crate::types::{Ability, Caveats, Resource};
use crate::util;
use sea_orm::{
    sea_query::NullOrdering, ColumnTrait, Condition, ConnectionTrait, DbErr, EntityTrait, Order,
    QueryFilter, QueryOrder, QuerySelect,
};
use time::OffsetDateTime;
use tinycloud_auth::resource::{Path, Service, SpaceId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TouchedTables {
    Supported(Vec<String>),
    Unsupported,
}

impl TouchedTables {
    pub fn supported(tables: Vec<String>) -> Self {
        Self::Supported(tables)
    }

    pub fn unsupported() -> Self {
        Self::Unsupported
    }

    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Supported(_))
    }

    pub fn tables(&self) -> Option<&[String]> {
        match self {
            Self::Supported(tables) => Some(tables),
            Self::Unsupported => None,
        }
    }
}

/// An unambiguous event path for a database and table. Both components are
/// encoded independently, so a slash in either can never move their boundary.
/// `n` and `p` distinguish a pathless database from an explicitly empty path.
pub fn db_table_path(db_path: Option<&str>, table_name: &str) -> String {
    let database = match db_path {
        None => "n".to_string(),
        Some(path) => format!("p{}", hex::encode(path.as_bytes())),
    };
    format!("db/{database}/table/{}", hex::encode(table_name.as_bytes()))
}

/// SQL/DuckDB subscriptions address database resources, independent of the
/// encoded event path. Non-slash scopes are exact; slash scopes are namespaces.
pub fn database_scope_matches(scope: Option<&str>, database_path: Option<&str>) -> bool {
    match (scope, database_path) {
        (None, _) => true,
        (Some(scope), Some(path)) if scope.ends_with('/') => path.starts_with(scope),
        (Some(scope), Some(path)) => path == scope,
        (Some(_), None) => false,
    }
}

pub fn database_subscription_matches_event(
    subscription: &hook_subscription::Model,
    database_path: Option<&str>,
    ability: &str,
) -> bool {
    database_scope_matches(subscription.path_prefix.as_deref(), database_path)
        && subscription
            .abilities()
            .is_ok_and(|abilities| abilities.is_empty() || abilities.iter().any(|a| a == ability))
}

pub fn subscription_matches_event(
    subscription: &hook_subscription::Model,
    path: &str,
    ability: &str,
) -> bool {
    if !matches_prefix(subscription.path_prefix.as_deref(), path) {
        return false;
    }

    match subscription.abilities() {
        Ok(abilities) => {
            abilities.is_empty() || abilities.iter().any(|candidate| candidate == ability)
        }
        Err(_) => false,
    }
}

pub fn hook_delivery_id(subscription_id: &str, event_id: &str) -> String {
    let mut hasher = Blake3Hasher::new();
    hasher.update(subscription_id.as_bytes());
    hasher.update(b":");
    hasher.update(event_id.as_bytes());
    hasher.finalize().to_cid(0x55).to_string()
}

fn matches_prefix(prefix: Option<&str>, path: &str) -> bool {
    match prefix.and_then(normalize_prefix) {
        None => true,
        Some(prefix) => path == prefix || path.starts_with(&format!("{prefix}/")),
    }
}

fn normalize_prefix(prefix: &str) -> Option<&str> {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// TC-991: Policy/v3 session and root delegations are never ordinary hook
/// authority (same exclusion as node-server `owner_holds_capabilities`).
const POLICY_DELEGATION_FACTS: [&str; 2] = [
    "xyz.tinycloud.policy/session-fact",
    "xyz.tinycloud.policy/root-profile",
];
const MAX_HOOK_AUTHORITY_ROWS: u64 = 256;
const MAX_HOOK_AUTHORITY_ATTEMPTS: usize = 32;
const HOOK_REGISTER: &str = "tinycloud.hooks/register";

/// TC-991: whether `holder` holds `tinycloud.hooks/register` on the hooks
/// scope `scope_path` (`kv/documents`, `sql/main.db`, ...) of `space_id` at
/// `now`, as space root authority or through one of its own delegations, by
/// the rules an invocation is authorized with (whole-chain revocation, every
/// chain window, caveat containment). `Ok(false)` is a definitive denial;
/// `Err` is transient and must not deactivate anything.
pub async fn hook_register_authority_holds<C: ConnectionTrait>(
    db: &C,
    holder: &str,
    space_id: &str,
    scope_path: &str,
    now: OffsetDateTime,
) -> Result<bool, DbErr> {
    let (Ok(space), Ok(service), Ok(path)) = (
        space_id.parse::<SpaceId>(),
        "hooks".parse::<Service>(),
        scope_path.parse::<Path>(),
    ) else {
        return Ok(false);
    };
    let resource = Resource::TinyCloud(space.clone().to_resource(service, Some(path), None, None));
    let cap = |caveats| util::Capability {
        resource: resource.clone(),
        ability: Ability::try_from(HOOK_REGISTER.to_string())
            .expect("valid hooks/register ability"),
        caveats,
    };
    let holder_principal = match tinycloud_auth::identity::principal_did(holder) {
        Ok(principal) => principal,
        Err(_) => return Ok(false),
    };
    let scope = [space.to_string()];
    match invocation::authorize_holder(db, holder, &[cap(Caveats(Default::default()))], &[], now)
        .await
    {
        Ok(()) => {
            let principals = [holder_principal.clone(), space.did().to_string()];
            return match crate::key_authority::check_principals(db, &principals, &scope).await {
                Ok(()) => Ok(true),
                Err(error) if crate::key_authority::is_revoked_error(&error) => Ok(false),
                Err(error) => Err(error),
            };
        }
        Err(invocation::Error::Db(error)) => return Err(error),
        Err(invocation::Error::InvalidInvocation(_)) => {}
    }
    let principal = holder_principal.as_str();
    let candidates = delegation::Entity::find()
        .filter(
            Condition::any()
                .add(delegation::Column::Delegatee.eq(principal))
                .add(delegation::Column::Delegatee.like(format!("{principal}#%")))
                .add(delegation::Column::Delegatee.eq(holder)),
        )
        .filter(
            Condition::any()
                .add(delegation::Column::Expiry.is_null())
                .add(delegation::Column::Expiry.gt(now)),
        )
        .order_by_with_nulls(
            delegation::Column::IssuedAt,
            Order::Desc,
            NullOrdering::Last,
        )
        .limit(MAX_HOOK_AUTHORITY_ROWS)
        .all(db)
        .await?
        .into_iter()
        .filter(|row| {
            !row.facts.as_ref().is_some_and(|facts| {
                POLICY_DELEGATION_FACTS
                    .iter()
                    .any(|key| facts.0.contains_key(*key))
            })
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Ok(false);
    }
    let rows = abilities::Entity::find()
        .filter(abilities::Column::Delegation.is_in(candidates.iter().map(|row| row.id)))
        .all(db)
        .await?;
    let mut attempts = 0;
    for candidate in &candidates {
        for row in rows.iter().filter(|row| {
            row.delegation == candidate.id
                && crate::policy_capability::ability_matches(
                    row.ability.as_ref().as_ref(),
                    HOOK_REGISTER,
                )
                && row
                    .resource
                    .tinycloud_resource()
                    .is_some_and(|id| id.space() == &space && id.service().as_str() == "hooks")
        }) {
            if attempts >= MAX_HOOK_AUTHORITY_ATTEMPTS {
                return Ok(false);
            }
            attempts += 1;
            match invocation::authorize_holder(
                db,
                holder,
                &[cap(row.caveats.clone())],
                &[candidate.id.to_cid(0x55)],
                now,
            )
            .await
            {
                Ok(()) => {
                    let mut principals =
                        match crate::auth_graph::load_chain_principals(db, &[candidate.id]).await {
                            Ok(principals) => principals,
                            Err(crate::auth_graph::ChainTraversalError::LimitExceeded) => continue,
                            Err(crate::auth_graph::ChainTraversalError::Db(DbErr::Custom(
                                reason,
                            ))) if matches!(
                                reason.as_str(),
                                "authorization-chain-missing" | "authorization-principal-invalid"
                            ) =>
                            {
                                continue;
                            }
                            Err(crate::auth_graph::ChainTraversalError::Db(error)) => {
                                return Err(error)
                            }
                        };
                    principals.push(holder_principal.clone());
                    match crate::key_authority::check_principals(db, &principals, &scope).await {
                        Ok(()) => return Ok(true),
                        Err(error) if crate::key_authority::is_revoked_error(&error) => continue,
                        Err(error) => return Err(error),
                    }
                }
                Err(invocation::Error::Db(error)) => return Err(error),
                Err(invocation::Error::InvalidInvocation(_)) => {}
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use crate::models::{actor, revocation};
    use crate::relationships::parent_delegations;
    use crate::types::Facts;
    use sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection,
        DbBackend, Statement,
    };
    use sea_orm_migration::MigratorTrait;

    const AUTHORITY_SPACE: &str =
        "tinycloud:key:z6Mkpcii8rkJV79k3JV37Wm5utAU6WkRsziqXf6mpMs734vB:files";

    async fn assert_hook_register_authority(db: &DatabaseConnection) {
        let space = AUTHORITY_SPACE.parse::<SpaceId>().unwrap();
        let owner = space.did().to_string();
        let now = OffsetDateTime::now_utc();
        let suffix = now.unix_timestamp_nanos();
        actor::ActiveModel {
            id: Set(owner.clone()),
        }
        .insert(db)
        .await
        .unwrap();
        assert!(
            hook_register_authority_holds(db, &owner, AUTHORITY_SPACE, "kv/documents", now)
                .await
                .unwrap()
        );

        for case in [
            "Live",
            "Revoked",
            "Expired",
            "NarrowPath",
            "NarrowAbility",
            "PolicySession",
            "RevokedParent",
            "LiveChain",
        ] {
            let holder = format!("did:key:z6MkTc991{case}{suffix}");
            actor::ActiveModel {
                id: Set(holder.clone()),
            }
            .insert(db)
            .await
            .unwrap();
            let id = crate::hash::hash(format!("tc991-{case}-{suffix}").as_bytes());
            let mut delegator = owner.clone();
            let mut parent = None;
            if matches!(case, "RevokedParent" | "LiveChain") {
                delegator = format!("did:key:z6MkTc991{case}Intermediate{suffix}");
                actor::ActiveModel {
                    id: Set(delegator.clone()),
                }
                .insert(db)
                .await
                .unwrap();
                let parent_id =
                    crate::hash::hash(format!("tc991-parent-{case}-{suffix}").as_bytes());
                delegation::ActiveModel {
                    id: Set(parent_id),
                    delegator: Set(owner.clone()),
                    delegatee: Set(delegator.clone()),
                    expiry: Set(Some(now + time::Duration::hours(2))),
                    issued_at: Set(Some(now)),
                    not_before: Set(None),
                    facts: Set(None),
                    serialization: Set(vec![]),
                }
                .insert(db)
                .await
                .unwrap();
                abilities::ActiveModel {
                    delegation: Set(parent_id),
                    resource: Set(Resource::TinyCloud(space.clone().to_resource(
                        "hooks".parse().unwrap(),
                        Some("kv/documents".parse().unwrap()),
                        None,
                        None,
                    ))),
                    ability: Set(Ability::try_from(HOOK_REGISTER.to_string()).unwrap()),
                    caveats: Set(Caveats::default()),
                }
                .insert(db)
                .await
                .unwrap();
                parent = Some(parent_id);
            }
            delegation::ActiveModel {
                id: Set(id),
                delegator: Set(delegator),
                delegatee: Set(holder.clone()),
                expiry: Set(Some(if case == "Expired" {
                    now - time::Duration::seconds(1)
                } else {
                    now + time::Duration::hours(1)
                })),
                issued_at: Set(Some(now)),
                not_before: Set(None),
                facts: Set((case == "PolicySession").then(|| {
                    Facts(std::collections::BTreeMap::from([(
                        POLICY_DELEGATION_FACTS[0].to_string(),
                        serde_json::json!({}),
                    )]))
                })),
                serialization: Set(vec![]),
            }
            .insert(db)
            .await
            .unwrap();
            let path = if case == "NarrowPath" {
                "kv/documents/public"
            } else {
                "kv/documents"
            };
            let ability = if case == "NarrowAbility" {
                "tinycloud.hooks/list"
            } else {
                HOOK_REGISTER
            };
            abilities::ActiveModel {
                delegation: Set(id),
                resource: Set(Resource::TinyCloud(space.clone().to_resource(
                    "hooks".parse().unwrap(),
                    Some(path.parse().unwrap()),
                    None,
                    None,
                ))),
                ability: Set(Ability::try_from(ability.to_string()).unwrap()),
                caveats: Set(Caveats::default()),
            }
            .insert(db)
            .await
            .unwrap();
            if let Some(parent) = parent {
                parent_delegations::ActiveModel {
                    parent: Set(parent),
                    child: Set(id),
                }
                .insert(db)
                .await
                .unwrap();
            }
            if matches!(case, "Revoked" | "RevokedParent") {
                revocation::ActiveModel {
                    id: Set(crate::hash::hash(
                        format!("tc991-revoke-{case}-{suffix}").as_bytes(),
                    )),
                    revoker: Set(owner.clone()),
                    revoked: Set(parent.unwrap_or(id)),
                    serialization: Set(vec![]),
                    revoked_at: Set(Some(now)),
                }
                .insert(db)
                .await
                .unwrap();
            }
            let invoker = if case == "Live" {
                format!("{holder}#{}", holder.strip_prefix("did:key:").unwrap())
            } else {
                holder
            };
            assert_eq!(
                hook_register_authority_holds(db, &invoker, AUTHORITY_SPACE, "kv/documents", now)
                    .await
                    .unwrap(),
                matches!(case, "Live" | "LiveChain"),
                "{case}"
            );
        }
    }

    #[tokio::test]
    async fn hook_register_authority_holds_tracks_live_authority() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        assert_hook_register_authority(&db).await;
    }

    #[tokio::test]
    async fn postgres_hook_register_authority_holds_tracks_live_authority() {
        let Some(url) = crate::test_support::postgres_test_url(
            "postgres_hook_register_authority_holds_tracks_live_authority",
        ) else {
            return;
        };
        let admin = Database::connect(ConnectOptions::new(url.clone()))
            .await
            .unwrap();
        let schema = format!(
            "tc991_{}_{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        admin
            .execute(Statement::from_string(
                DbBackend::Postgres,
                format!("CREATE SCHEMA {schema}"),
            ))
            .await
            .unwrap();
        let mut options = ConnectOptions::new(url);
        options
            .max_connections(4)
            .sqlx_logging(false)
            .set_schema_search_path(schema.clone());
        let db = Database::connect(options).await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        assert_hook_register_authority(&db).await;
        db.close().await.unwrap();
        admin
            .execute(Statement::from_string(
                DbBackend::Postgres,
                format!("DROP SCHEMA {schema} CASCADE"),
            ))
            .await
            .unwrap();
    }

    fn test_subscription(
        path_prefix: Option<&str>,
        abilities: &[&str],
    ) -> hook_subscription::Model {
        hook_subscription::Model {
            id: "sub_01".to_string(),
            subscriber_did: "did:key:test".to_string(),
            space_id: "tinycloud:space".to_string(),
            target_service: "sql".to_string(),
            path_prefix: path_prefix.map(ToString::to_string),
            abilities_json: hook_subscription::Model::set_abilities(
                &abilities
                    .iter()
                    .map(|ability| ability.to_string())
                    .collect::<Vec<_>>(),
            ),
            callback_url: "https://example.com/hooks".to_string(),
            encrypted_secret: vec![1, 2, 3],
            secret_key_id: "primary".to_string(),
            active: true,
            created_at: "2026-04-09T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn subscription_matches_event_enforces_prefix_and_ability() {
        let subscription = test_subscription(Some("/analytics/"), &["tinycloud.sql/write"]);
        assert!(subscription_matches_event(
            &subscription,
            "analytics/users",
            "tinycloud.sql/write"
        ));
        assert!(!subscription_matches_event(
            &subscription,
            "billing/users",
            "tinycloud.sql/write"
        ));
        assert!(!subscription_matches_event(
            &subscription,
            "analytics/users",
            "tinycloud.sql/read"
        ));
    }

    #[test]
    fn subscription_matches_event_rejects_invalid_ability_json() {
        let mut subscription = test_subscription(None, &[]);
        subscription.abilities_json = Some("{".to_string());
        assert!(!subscription_matches_event(
            &subscription,
            "analytics/users",
            "tinycloud.sql/write"
        ));
    }

    #[test]
    fn hook_delivery_id_is_stable_for_same_inputs() {
        let left = hook_delivery_id("sub_01", "event_01");
        let right = hook_delivery_id("sub_01", "event_01");
        let other = hook_delivery_id("sub_02", "event_01");
        assert_eq!(left, right);
        assert_ne!(left, other);
    }

    #[test]
    fn database_event_paths_have_unambiguous_components() {
        assert_ne!(
            db_table_path(None, "items"),
            db_table_path(Some("default"), "items")
        );
        assert_ne!(
            db_table_path(Some("appA/connectors"), "private/items"),
            db_table_path(Some("appA/connectors/private"), "items")
        );
        assert_ne!(
            db_table_path(Some(""), "items"),
            db_table_path(None, "items")
        );
    }

    #[test]
    fn database_hook_scopes_follow_exact_and_slash_grants() {
        let exact = test_subscription(Some("appA/connectors"), &["tinycloud.sql/write"]);
        assert!(database_subscription_matches_event(
            &exact,
            Some("appA/connectors"),
            "tinycloud.sql/write"
        ));
        assert!(!database_subscription_matches_event(
            &exact,
            Some("appA/connectors/private"),
            "tinycloud.sql/write"
        ));
        let namespace = test_subscription(Some("appA/connectors/"), &[]);
        assert!(database_subscription_matches_event(
            &namespace,
            Some("appA/connectors/private"),
            "tinycloud.sql/write"
        ));
        assert!(!database_subscription_matches_event(
            &exact,
            None,
            "tinycloud.sql/write"
        ));
        let default = test_subscription(Some("default"), &[]);
        assert!(database_subscription_matches_event(
            &default,
            Some("default"),
            "tinycloud.sql/write"
        ));
        assert!(!database_subscription_matches_event(
            &default,
            None,
            "tinycloud.sql/write"
        ));
    }
}
