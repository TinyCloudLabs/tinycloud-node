use sea_orm::entity::prelude::*;

/// A nonce minted for held-credential presentation, bound to one audience and
/// one canonical `did:pkh:eip155` account. A row is spent by deleting it, so
/// the table holds only unspent nonces.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "held_credential_nonce")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub audience: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub nonce: String,
    pub account: String,
    /// Unix seconds after which the nonce can no longer be spent.
    pub expires_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
