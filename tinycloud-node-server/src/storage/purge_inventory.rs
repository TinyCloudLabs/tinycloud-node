//! Exact store-relative physical namespace inventory. Ledger authentication is
//! separate; these values are candidates until their keyed prefix identity matches.
use tinycloud_auth::resource::SpaceId;

#[derive(Debug, Clone)]
pub struct PhysicalSpacePrefix {
    pub space: SpaceId,
    pub prefix: String,
}
#[derive(Debug)]
pub struct SpacePrefixPage {
    pub prefixes: Vec<PhysicalSpacePrefix>,
    /// Backend-local opaque pagination token; never a deletion resume cursor.
    pub next_cursor: Option<String>,
}
