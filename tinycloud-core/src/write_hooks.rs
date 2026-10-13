use crate::hash::Blake3Hasher;
use crate::models::hook_subscription;

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

#[cfg(test)]
mod tests {
    use super::*;

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
