use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tinycloud_lib::resource::SpaceId;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Eq, Hash, PartialOrd, Ord)]
pub struct SpaceIdWrap(pub SpaceId);

impl From<SpaceId> for SpaceIdWrap {
    fn from(id: SpaceId) -> Self {
        Self(id)
    }
}

impl From<SpaceIdWrap> for SpaceId {
    fn from(id: SpaceIdWrap) -> Self {
        id.0
    }
}

impl AsRef<SpaceId> for SpaceIdWrap {
    fn as_ref(&self) -> &SpaceId {
        &self.0
    }
}

impl core::borrow::Borrow<SpaceId> for SpaceIdWrap {
    fn borrow(&self) -> &SpaceId {
        &self.0
    }
}

impl PartialEq<SpaceId> for SpaceIdWrap {
    fn eq(&self, other: &SpaceId) -> bool {
        self.0 == *other
    }
}

impl From<SpaceIdWrap> for Value {
    fn from(o: SpaceIdWrap) -> Self {
        Value::String(Some(Box::new(o.0.to_string())))
    }
}

impl sea_orm::TryGetable for SpaceIdWrap {
    fn try_get_by<I: sea_orm::ColIdx>(
        res: &QueryResult,
        idx: I,
    ) -> Result<Self, sea_orm::TryGetError> {
        let s: String = res.try_get_by(idx).map_err(sea_orm::TryGetError::DbErr)?;
        Ok(SpaceIdWrap(SpaceId::from_str(&s).map_err(|e| {
            sea_orm::TryGetError::DbErr(DbErr::TryIntoErr {
                from: "String",
                into: "SpaceId",
                source: Box::new(e),
            })
        })?))
    }
}

impl sea_orm::sea_query::ValueType for SpaceIdWrap {
    fn try_from(v: Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
        match v {
            Value::String(Some(x)) => Ok(SpaceId::from_str(&x)
                .map_err(|_| sea_orm::sea_query::ValueTypeErr)?
                .into()),
            _ => Err(sea_orm::sea_query::ValueTypeErr),
        }
    }

    fn type_name() -> String {
        stringify!(SpaceId).to_owned()
    }

    fn array_type() -> sea_orm::sea_query::ArrayType {
        sea_orm::sea_query::ArrayType::String
    }

    fn column_type() -> sea_orm::sea_query::ColumnType {
        sea_orm::sea_query::ColumnType::String(sea_orm::sea_query::StringLen::Max)
    }
}

impl sea_orm::sea_query::Nullable for SpaceIdWrap {
    fn null() -> Value {
        Value::String(None)
    }
}

impl sea_orm::TryFromU64 for SpaceIdWrap {
    fn try_from_u64(_: u64) -> Result<Self, DbErr> {
        Err(DbErr::ConvertFromU64(stringify!($type)))
    }
}
