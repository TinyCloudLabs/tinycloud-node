use sea_orm::entity::prelude::*;
use sea_orm::DbErr;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum KeyRevokeError {
    #[error("key revocation forbidden")]
    Forbidden,
    #[error("key revocation nonce conflict")]
    Conflict,
    #[error("key revocation database unavailable")]
    Db {
        #[source]
        source: DbErr,
        write_may_have_applied: bool,
    },
}

/// The signed scope; a space revocation never confers global authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum KeyRevokeScope {
    Global,
    Space {
        #[serde(rename = "spaceId")]
        space_id: String,
    },
}

impl KeyRevokeScope {
    pub fn storage_key(&self) -> String {
        match self {
            Self::Global => "global".into(),
            Self::Space { space_id } => format!("space:{space_id}"),
        }
    }
}

/// Only the node's signature-verification boundary may construct this input.
/// Database authorization of the authenticated actor and proof chain follows
/// inside the transaction, before any nonce/tombstone diagnostics are exposed.
#[derive(Clone, Debug)]
pub struct VerifiedKeyRevoke {
    pub target_did: String,
    pub issuer_did: String,
    pub scope: KeyRevokeScope,
    pub nonce: String,
    pub authorization_hash: [u8; 32],
    pub proof_cids: Vec<String>,
    pub not_before: i64,
    /// SIWE/CACAO's optional signed `nbf`; UCAN's `nbf` is `not_before` itself.
    pub valid_after: Option<i64>,
    pub expires_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyRevokeReceipt {
    pub revoked: bool,
    pub target_did: String,
    pub scope: KeyRevokeScope,
    pub revoked_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "key_revocation")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub target_did: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub scope_key: String,
    pub revoked_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// A row per principal ensures that global and scoped writes targeting the
/// same DID serialize in all supported database backends.
pub mod target {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "key_revocation_target")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub target_did: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod nonce {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "key_revocation_nonce")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub issuer_did: String,
        #[sea_orm(primary_key, auto_increment = false)]
        pub nonce: String,
        pub authorization_hash: Vec<u8>,
        pub target_did: String,
        pub receipt_bytes: Vec<u8>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
