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

pub fn db_table_path(db_name: &str, table_name: &str) -> String {
    format!("{db_name}/{table_name}")
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
}
