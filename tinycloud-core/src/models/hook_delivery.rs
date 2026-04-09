use super::hook_subscription;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "hook_delivery")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub id: String,
    pub subscription_id: String,
    pub event_id: String,
    pub payload_json: String,
    pub status: String,
    pub attempts: i64,
    pub next_attempt_at: Option<String>,
    pub last_error: Option<String>,
    pub created_at: String,
    pub delivered_at: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "hook_subscription::Entity",
        from = "Column::SubscriptionId",
        to = "hook_subscription::Column::Id"
    )]
    Subscription,
}

impl Related<hook_subscription::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Subscription.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
