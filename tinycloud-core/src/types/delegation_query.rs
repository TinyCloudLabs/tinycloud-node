use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::Caveats;

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DelegationQueryDirection {
    Granted,
    Received,
    #[default]
    All,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DelegationQueryStatus {
    Active,
    Pending,
    Expired,
    Revoked,
    AncestorRevoked,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DelegationQuery {
    #[serde(default)]
    pub direction: DelegationQueryDirection,
    pub status: Option<DelegationQueryStatus>,
    pub space: Option<String>,
    pub limit: Option<u16>,
    pub cursor: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum DelegationQueryValidationError {
    #[error("limit must be between 1 and 100")]
    InvalidLimit,
    #[error("space must not be empty")]
    InvalidSpace,
    #[error("invalid delegation query cursor")]
    InvalidCursor,
}

impl DelegationQuery {
    pub fn validate(&self) -> Result<(), DelegationQueryValidationError> {
        if self.limit.is_some_and(|limit| !(1..=100).contains(&limit)) {
            return Err(DelegationQueryValidationError::InvalidLimit);
        }
        if self
            .space
            .as_ref()
            .is_some_and(|space| space.trim().is_empty())
        {
            return Err(DelegationQueryValidationError::InvalidSpace);
        }
        if self.cursor.is_some() {
            self.decoded_cursor()?;
        }
        Ok(())
    }

    pub fn decoded_cursor(&self) -> Result<Option<String>, DelegationQueryValidationError> {
        self.cursor
            .as_deref()
            .map(|cursor| {
                URL_SAFE_NO_PAD
                    .decode(cursor)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .filter(|cid| !cid.is_empty())
                    .ok_or(DelegationQueryValidationError::InvalidCursor)
            })
            .transpose()
    }

    pub fn encode_cursor(cid: &str) -> String {
        URL_SAFE_NO_PAD.encode(cid.as_bytes())
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegationQueryPage {
    pub schema_version: u8,
    pub items: Vec<AccountDelegationRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountDelegationRecord {
    pub cid: String,
    pub direction: String,
    pub delegator_did: String,
    pub delegate_did: String,
    pub resources: Vec<DelegationResource>,
    pub parents: Vec<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub issued_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub not_before: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_ancestor_cid: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegationResource {
    pub resource: String,
    pub actions: Vec<String>,
    pub caveats: Vec<Caveats>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_filters_and_out_of_range_limits() {
        assert!(
            serde_json::from_value::<DelegationQuery>(serde_json::json!({
                "direction": "sideways"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<DelegationQuery>(serde_json::json!({
                "unknown": true
            }))
            .is_err()
        );
        let query: DelegationQuery = serde_json::from_value(serde_json::json!({
            "limit": 101
        }))
        .unwrap();
        assert!(matches!(
            query.validate(),
            Err(DelegationQueryValidationError::InvalidLimit)
        ));
    }

    #[test]
    fn cursor_is_opaque_and_round_trips() {
        let cid = "bafyreigaccountdelegation";
        let cursor = DelegationQuery::encode_cursor(cid);
        assert_ne!(cursor, cid);
        let query: DelegationQuery = serde_json::from_value(serde_json::json!({
            "cursor": cursor
        }))
        .unwrap();
        assert_eq!(query.decoded_cursor().unwrap().as_deref(), Some(cid));
        let invalid: DelegationQuery = serde_json::from_value(serde_json::json!({
            "cursor": "%%%"
        }))
        .unwrap();
        assert!(invalid.validate().is_err());
    }
}
