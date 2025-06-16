use iri_string::types::UriString;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};
use tinycloud_lib::resource::{OrbitId, ResourceId};

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[serde(untagged)]
pub enum Resource {
    TinyCloud(ResourceId),
    Other(UriString),
}

impl Resource {
    pub fn orbit(&self) -> Option<&OrbitId> {
        match self {
            Resource::TinyCloud(id) => Some(id.orbit()),
            Resource::Other(_) => None,
        }
    }

    pub fn extends(&self, other: &Self) -> bool {
        match (self, other) {
            (Resource::TinyCloud(a), Resource::TinyCloud(b)) => a.extends(b).is_ok(),
            (Resource::Other(a), Resource::Other(b)) => a.as_str().starts_with(b.as_str()),
            _ => false,
        }
    }

    pub fn tinycloud_resource(&self) -> Option<&ResourceId> {
        match self {
            Resource::TinyCloud(id) => Some(id),
            Resource::Other(_) => None,
        }
    }
}

impl From<ResourceId> for Resource {
    fn from(id: ResourceId) -> Self {
        Resource::TinyCloud(id)
    }
}

impl From<Resource> for Value {
    fn from(r: Resource) -> Self {
        Value::String(Some(Box::new(r.to_string())))
    }
}

impl sea_orm::TryGetable for Resource {
    fn try_get_by<I: sea_orm::ColIdx>(
        res: &QueryResult,
        idx: I,
    ) -> Result<Self, sea_orm::TryGetError> {
        let s: String = res.try_get_by(idx).map_err(sea_orm::TryGetError::DbErr)?;
        Ok(s.parse().map_err(|e| sea_orm::DbErr::TryIntoErr {
            from: stringify!(String),
            into: stringify!(Resource),
            source: Box::new(e),
        })?)
    }
}

impl sea_orm::sea_query::ValueType for Resource {
    fn try_from(v: Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
        match v {
            Value::String(Some(x)) => Ok(Resource::from_str(&x)?),
            _ => Err(sea_orm::sea_query::ValueTypeErr),
        }
    }

    fn type_name() -> String {
        stringify!(Resource).to_owned()
    }

    fn array_type() -> sea_orm::sea_query::ArrayType {
        sea_orm::sea_query::ArrayType::String
    }

    fn column_type() -> sea_orm::sea_query::ColumnType {
        sea_orm::sea_query::ColumnType::String(None)
    }
}

impl FromStr for Resource {
    type Err = iri_string::validate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if let Ok(resource_id) = ResourceId::from_str(s) {
            Resource::TinyCloud(resource_id)
        } else {
            Resource::Other(UriString::from_str(s)?)
        })
    }
}

impl Display for Resource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Resource::TinyCloud(resource_id) => write!(f, "{}", resource_id),
            Resource::Other(s) => write!(f, "{}", s),
        }
    }
}

impl sea_orm::sea_query::Nullable for Resource {
    fn null() -> Value {
        Value::String(None)
    }
}

impl sea_orm::TryFromU64 for Resource {
    fn try_from_u64(_: u64) -> Result<Self, DbErr> {
        Err(DbErr::ConvertFromU64(stringify!($type)))
    }
}
