use sea_orm::{entity::prelude::*, sea_query::ValueTypeErr};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};
use tinycloud_lib::resource::{
    iri_string::{
        types::{UriStr, UriString},
        validate::Error as UriError,
    },
    KRIParseError, OrbitId, ResourceId,
};

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
        match res.try_get_by::<String, I>(idx) {
            Ok(r) => r.parse().map_err(|e| DbErr::TryIntoErr {
                from: "String",
                into: "Resource",
                source: Box::new(e),
            }),
            Err(e) => Err(e),
        }
        .map_err(sea_orm::TryGetError::DbErr)
    }
}

// tinycloud:<method>:<method-specific-id>:<id>
// tinycloud:<method>:<method-specific-id>:<id>/<service>/<path>#<fragment>?<query>

// id = "tinycloud:" method-name ":" method-specific-id ":" name
// name     = 1*nchar
// method-name        = 1*method-char
// method-char        = %x61-7A / DIGIT
// method-specific-id = *( *idchar ":" ) 1*idchar
// idchar             = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
// pct-encoded        = "%" HEXDIG HEXDIG
// nchar         = unreserved / pct-encoded / sub-delims / "@"
// unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
// sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
//             / "*" / "+" / "," / ";" / "="

// resource = id "/" service  [ "/" path ] [ "?" query ] [ "#" fragment ]
// service = 1*nchar
// path = *( segment "/" ) segment
// segment       = *pchar
// pchar         = nchar / ":"
// query         = *( pchar / "/" / "?" )
// fragment      = *( pchar / "/" / "?" )

impl sea_orm::sea_query::ValueType for Resource {
    fn try_from(v: Value) -> Result<Self, ValueTypeErr> {
        match v {
            Value::String(Some(x)) => x.parse().map_err(|_| ValueTypeErr),
            _ => Err(ValueTypeErr),
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

impl From<&UriStr> for Resource {
    fn from(uri: &UriStr) -> Self {
        match ResourceId::try_from(uri) {
            Ok(r) => Self::TinyCloud(r),
            _ => Self::Other(uri.into()),
        }
    }
}

impl From<UriString> for Resource {
    fn from(uri: UriString) -> Self {
        match ResourceId::try_from(uri.as_slice()) {
            Ok(r) => Self::TinyCloud(r),
            _ => Self::Other(uri),
        }
    }
}

impl From<&UriString> for Resource {
    fn from(uri: &UriString) -> Self {
        Self::from(uri.as_slice())
    }
}

impl FromStr for Resource {
    type Err = UriError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match ResourceId::from_str(s) {
            Ok(r) => Ok(Self::TinyCloud(r)),
            Err(KRIParseError::UriStringParse(e)) => Err(e),
            _ => UriString::from_str(s).map(Self::Other),
        }
    }
}

impl Display for Resource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Resource::TinyCloud(resource_id) => write!(f, "{resource_id}"),
            Resource::Other(s) => write!(f, "{s}"),
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
