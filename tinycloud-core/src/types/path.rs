use sea_orm::{entity::prelude::*, sea_query::ValueTypeErr};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use tinycloud_lib::resource::{KRIParseError, Path as LibPath};

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Path(pub LibPath);

impl AsRef<LibPath> for Path {
    fn as_ref(&self) -> &LibPath {
        &self.0
    }
}

impl From<Path> for Value {
    fn from(r: Path) -> Self {
        Value::String(Some(Box::new(r.to_string())))
    }
}

impl sea_orm::TryGetable for Path {
    fn try_get_by<I: sea_orm::ColIdx>(
        res: &QueryResult,
        idx: I,
    ) -> Result<Self, sea_orm::TryGetError> {
        let s: String = res.try_get_by(idx).map_err(sea_orm::TryGetError::DbErr)?;
        Ok(Path::try_from(s).map_err(|e| DbErr::TryIntoErr {
            from: "String",
            into: "Path",
            source: Box::new(e),
        })?)
    }
}

impl sea_orm::sea_query::ValueType for Path {
    fn try_from(v: Value) -> Result<Self, ValueTypeErr> {
        match v {
            Value::String(Some(x)) => (*x).try_into().map_err(|_| ValueTypeErr),
            _ => Err(ValueTypeErr),
        }
    }

    fn type_name() -> String {
        stringify!(Path).to_owned()
    }

    fn array_type() -> sea_orm::sea_query::ArrayType {
        sea_orm::sea_query::ArrayType::String
    }

    fn column_type() -> sea_orm::sea_query::ColumnType {
        sea_orm::sea_query::ColumnType::String(None)
    }
}

impl From<LibPath> for Path {
    fn from(ab: LibPath) -> Self {
        Self(ab)
    }
}

impl TryFrom<String> for Path {
    type Error = KRIParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Ok(Path(LibPath::try_from(s)?))
    }
}

impl Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl sea_orm::sea_query::Nullable for Path {
    fn null() -> Value {
        Value::String(None)
    }
}

impl sea_orm::TryFromU64 for Path {
    fn try_from_u64(_: u64) -> Result<Self, DbErr> {
        Err(DbErr::ConvertFromU64(stringify!($type)))
    }
}
