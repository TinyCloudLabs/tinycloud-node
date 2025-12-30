use sea_orm::{entity::prelude::*, sea_query::ValueTypeErr};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use ucan_capabilities_object::{ability::AbilityError, Ability as UcanAbility};

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ability(UcanAbility);

impl AsRef<UcanAbility> for Ability {
    fn as_ref(&self) -> &UcanAbility {
        &self.0
    }
}

impl From<Ability> for Value {
    fn from(r: Ability) -> Self {
        Value::String(Some(Box::new(r.to_string())))
    }
}

impl sea_orm::TryGetable for Ability {
    fn try_get_by<I: sea_orm::ColIdx>(
        res: &QueryResult,
        idx: I,
    ) -> Result<Self, sea_orm::TryGetError> {
        let s: String = res.try_get_by(idx).map_err(sea_orm::TryGetError::DbErr)?;
        Ok(Ability::try_from(s).map_err(|e| DbErr::TryIntoErr {
            from: "String",
            into: "Ability",
            source: Box::new(e),
        })?)
    }
}

impl sea_orm::sea_query::ValueType for Ability {
    fn try_from(v: Value) -> Result<Self, ValueTypeErr> {
        match v {
            Value::String(Some(x)) => (*x).try_into().map_err(|_| ValueTypeErr),
            _ => Err(ValueTypeErr),
        }
    }

    fn type_name() -> String {
        stringify!(Ability).to_owned()
    }

    fn array_type() -> sea_orm::sea_query::ArrayType {
        sea_orm::sea_query::ArrayType::String
    }

    fn column_type() -> sea_orm::sea_query::ColumnType {
        sea_orm::sea_query::ColumnType::String(sea_orm::sea_query::StringLen::Max)
    }
}

impl From<UcanAbility> for Ability {
    fn from(ab: UcanAbility) -> Self {
        Self(ab)
    }
}

impl TryFrom<String> for Ability {
    type Error = AbilityError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Ok(Ability(s.try_into()?))
    }
}

impl Display for Ability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl sea_orm::sea_query::Nullable for Ability {
    fn null() -> Value {
        Value::String(None)
    }
}

impl sea_orm::TryFromU64 for Ability {
    fn try_from_u64(_: u64) -> Result<Self, DbErr> {
        Err(DbErr::ConvertFromU64(stringify!($type)))
    }
}
