use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tinycloud_lib::resource::NamespaceId;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Eq, Hash, PartialOrd, Ord)]
pub struct NamespaceIdWrap(pub NamespaceId);

impl From<NamespaceId> for NamespaceIdWrap {
    fn from(id: NamespaceId) -> Self {
        Self(id)
    }
}

impl From<NamespaceIdWrap> for NamespaceId {
    fn from(id: NamespaceIdWrap) -> Self {
        id.0
    }
}

impl AsRef<NamespaceId> for NamespaceIdWrap {
    fn as_ref(&self) -> &NamespaceId {
        &self.0
    }
}

impl core::borrow::Borrow<NamespaceId> for NamespaceIdWrap {
    fn borrow(&self) -> &NamespaceId {
        &self.0
    }
}

impl PartialEq<NamespaceId> for NamespaceIdWrap {
    fn eq(&self, other: &NamespaceId) -> bool {
        self.0 == *other
    }
}

impl From<NamespaceIdWrap> for Value {
    fn from(o: NamespaceIdWrap) -> Self {
        Value::String(Some(Box::new(o.0.to_string())))
    }
}

impl sea_orm::TryGetable for NamespaceIdWrap {
    fn try_get_by<I: sea_orm::ColIdx>(
        res: &QueryResult,
        idx: I,
    ) -> Result<Self, sea_orm::TryGetError> {
        let s: String = res.try_get_by(idx).map_err(sea_orm::TryGetError::DbErr)?;
        Ok(NamespaceIdWrap(NamespaceId::from_str(&s).map_err(|e| {
            sea_orm::TryGetError::DbErr(DbErr::TryIntoErr {
                from: "String",
                into: "NamespaceId",
                source: Box::new(e),
            })
        })?))
    }
}

impl sea_orm::sea_query::ValueType for NamespaceIdWrap {
    fn try_from(v: Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
        match v {
            Value::String(Some(x)) => Ok(NamespaceId::from_str(&x)
                .map_err(|_| sea_orm::sea_query::ValueTypeErr)?
                .into()),
            _ => Err(sea_orm::sea_query::ValueTypeErr),
        }
    }

    fn type_name() -> String {
        stringify!(NamespaceId).to_owned()
    }

    fn array_type() -> sea_orm::sea_query::ArrayType {
        sea_orm::sea_query::ArrayType::String
    }

    fn column_type() -> sea_orm::sea_query::ColumnType {
        sea_orm::sea_query::ColumnType::String(sea_orm::sea_query::StringLen::Max)
    }
}

impl sea_orm::sea_query::Nullable for NamespaceIdWrap {
    fn null() -> Value {
        Value::String(None)
    }
}

impl sea_orm::TryFromU64 for NamespaceIdWrap {
    fn try_from_u64(_: u64) -> Result<Self, DbErr> {
        Err(DbErr::ConvertFromU64(stringify!($type)))
    }
}
