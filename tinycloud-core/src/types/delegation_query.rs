use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::Caveats;
use crate::hash::Hash;
use tinycloud_auth::ipld_core::cid::Cid;

const RAW_CODEC: u64 = 0x55;
const BLAKE3_256_CODE: u64 = 0x1e;

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DelegationQueryDirection {
    Granted,
    Received,
    /// Delegations whose delegator is the invoking principal itself. Has its
    /// own authorization path and keyset cursor (TC-2132).
    Issued,
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

impl DelegationQueryStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Pending => "pending",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::AncestorRevoked => "ancestor_revoked",
        }
    }
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

    /// Digest of everything an `issued` cursor is bound to: the invoker and
    /// the `status` / `space` filters. A cursor minted under another invoker
    /// or filter does not decode.
    fn issued_binding(&self, invoker: &str) -> String {
        let binding = serde_json::to_vec(&(
            "delegation-issued-query-v1",
            invoker,
            self.status.map(DelegationQueryStatus::label),
            self.space.as_deref(),
        ))
        .expect("a tuple of strings serializes");
        URL_SAFE_NO_PAD.encode(crate::hash::hash(&binding).as_ref())
    }

    /// Cursor for the `issued` direction: the last scanned row id plus the
    /// binding of invoker and filters.
    pub fn encode_issued_cursor(&self, invoker: &str, last: Hash) -> String {
        URL_SAFE_NO_PAD.encode(format!(
            "i1.{}.{}",
            last.to_cid(RAW_CODEC),
            self.issued_binding(invoker)
        ))
    }

    /// Decode an `issued` cursor into the row id to continue after. The id is
    /// only ever a key position inside the invoker's own rows; it is never
    /// looked up. Anything that is not a cursor minted for this invoker and
    /// these filters is `InvalidCursor`.
    pub fn decoded_issued_cursor(
        &self,
        invoker: &str,
    ) -> Result<Option<Hash>, DelegationQueryValidationError> {
        let Some(cursor) = self.cursor.as_deref() else {
            return Ok(None);
        };
        let invalid = || DelegationQueryValidationError::InvalidCursor;
        let text = URL_SAFE_NO_PAD
            .decode(cursor)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or_else(invalid)?;
        let mut parts = text.split('.');
        let (Some("i1"), Some(cid), Some(binding), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid());
        };
        if binding != self.issued_binding(invoker) {
            return Err(invalid());
        }
        let cid = Cid::try_from(cid).map_err(|_| invalid())?;
        if cid.codec() != RAW_CODEC
            || cid.hash().code() != BLAKE3_256_CODE
            || cid.hash().digest().len() != 32
        {
            return Err(invalid());
        }
        Ok(Some(Hash::from(cid)))
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
