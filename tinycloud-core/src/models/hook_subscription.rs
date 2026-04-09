use super::hook_delivery;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "hook_subscription")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub id: String,
    pub subscriber_did: String,
    pub space_id: String,
    pub target_service: String,
    pub path_prefix: Option<String>,
    pub abilities_json: Option<String>,
    pub callback_url: String,
    pub encrypted_secret: Vec<u8>,
    pub secret_key_id: String,
    pub active: bool,
    pub created_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "hook_delivery::Entity")]
    Deliveries,
}

impl Related<hook_delivery::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Deliveries.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub fn abilities(&self) -> Result<Vec<String>, serde_json::Error> {
        match self.abilities_json.as_deref() {
            Some(json) => serde_json::from_str(json),
            None => Ok(Vec::new()),
        }
    }

    pub fn set_abilities(abilities: &[String]) -> Option<String> {
        if abilities.is_empty() {
            None
        } else {
            Some(serde_json::to_string(abilities).expect("serializing abilities should not fail"))
        }
    }
}
