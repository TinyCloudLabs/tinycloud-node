//! One object of a threshold network's authorization set (TC-2225), stored by
//! the CID of its original bytes. Nothing is pruned; the rows of an erased
//! owner's networks go with the owner (`space_purge_database`).

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "threshold_set_object")]
pub struct Model {
    /// The network URN, `urn:tinycloud:encryption:<owner>:<name>`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub network_id: String,
    /// CID (raw codec) of `bytes`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub cid: String,
    /// `cert`, `activation`, `revocation` or `key-state`.
    pub kind: String,
    /// What the object is about: a certificate's digest (hex) for `cert` and
    /// the certificate it activates for `activation`, the revoked delegation's
    /// CID for `revocation`, the key path for `key-state` (empty for
    /// `network.revoke`).
    pub subject: String,
    /// The object exactly as received.
    pub bytes: Vec<u8>,
    pub recorded_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
