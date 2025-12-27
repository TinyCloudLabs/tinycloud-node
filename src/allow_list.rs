use anyhow::Result;
use reqwest::get;
use serde::{Deserialize, Serialize};
use tinycloud_lib::ipld_core::cid::{multibase::Base, Cid};
use tinycloud_lib::resource::NamespaceId;

#[rocket::async_trait]
pub trait NamespaceAllowList {
    async fn is_allowed(&self, oid: &Cid) -> Result<NamespaceId>;
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
#[serde(from = "String", into = "String")]
pub struct NamespaceAllowListService(pub String);

impl From<String> for NamespaceAllowListService {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<NamespaceAllowListService> for String {
    fn from(nals: NamespaceAllowListService) -> Self {
        nals.0
    }
}

#[rocket::async_trait]
impl NamespaceAllowList for NamespaceAllowListService {
    async fn is_allowed(&self, oid: &Cid) -> Result<NamespaceId> {
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
