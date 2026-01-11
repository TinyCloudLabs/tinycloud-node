use anyhow::Result;
use reqwest::get;
use serde::{Deserialize, Serialize};
use tinycloud_lib::ipld_core::cid::{multibase::Base, Cid};
use tinycloud_lib::resource::SpaceId;

#[rocket::async_trait]
pub trait SpaceAllowList {
    async fn is_allowed(&self, oid: &Cid) -> Result<SpaceId>;
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
#[serde(from = "String", into = "String")]
pub struct SpaceAllowListService(pub String);

impl From<String> for SpaceAllowListService {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<SpaceAllowListService> for String {
    fn from(nals: SpaceAllowListService) -> Self {
        nals.0
    }
}

#[rocket::async_trait]
impl SpaceAllowList for SpaceAllowListService {
    async fn is_allowed(&self, oid: &Cid) -> Result<SpaceId> {
        Ok(
            get([self.0.as_str(), &oid.to_string_of_base(Base::Base58Btc)?].join("/"))
                .await?
                .error_for_status()?
                .text()
                .await?
                .parse()?,
        )
    }
}
