//! The SQL abilities one invocation holds, and the node's policy for schema
//! changes (TC-1581).
//!
//! An invocation can carry several `tinycloud.sql/*` capabilities at once (the
//! SDK sends `[write, schema]` for `execute({ schema: [...] })` and for its
//! migrations helper). Authorization therefore cannot be decided from a single
//! "preferred" ability: a data statement is judged against the data
//! abilities held, a schema-changing statement against a schema-conferring
//! ability (`schema`, `admin`, `*`), and a request that mixes the two needs both.

use prometheus::{register_int_counter_vec, IntCounterVec};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

use crate::policy_capability::{ability_matches, resolve_alias};

const ADMIN: &str = "tinycloud.sql/admin";
const SCHEMA: &str = "tinycloud.sql/schema";
const WRITE: &str = "tinycloud.sql/write";
const READ: &str = "tinycloud.sql/read";

/// Whether a schema-changing statement needs a schema-conferring ability.
///
/// Configured as `[global.storage.sql] ddl_requires_schema`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DdlPolicy {
    /// A schema-changing statement runs with `write` or `schema` (the
    /// behaviour before TC-1581).
    Off,
    /// As `Off`, but a statement that `Enforce` would refuse is counted and
    /// logged once per request, with no request content in either.
    Log,
    /// A schema-changing statement needs `schema`, `admin` or `*`.
    #[default]
    Enforce,
}

/// The statement kind recorded in `Log` mode. A closed set: it is the only
/// label on the counter and never carries a name from the request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DdlKind {
    CreateTable,
    CreateView,
    CreateIndex,
    AlterTable,
    Drop,
}

impl DdlKind {
    pub fn as_str(self) -> &'static str {
        match self {
            DdlKind::CreateTable => "create_table",
            DdlKind::CreateView => "create_view",
            DdlKind::CreateIndex => "create_index",
            DdlKind::AlterTable => "alter_table",
            DdlKind::Drop => "drop",
        }
    }
}

static DDL_LOG_COUNTER: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "tinycloud_ddl_without_schema_total",
        "Schema-changing statements that were allowed only because ddl_requires_schema is \"log\".",
        &["service", "kind"]
    )
    .expect("ddl counter should register exactly once")
});

/// Count one statement that `Enforce` would have refused.
pub fn record_ddl_without_schema(kind: DdlKind) {
    DDL_LOG_COUNTER
        .with_label_values(&["sql", kind.as_str()])
        .inc();
}

/// Current value of the `Log`-mode counter for `kind` (tests).
pub fn ddl_without_schema_count(kind: DdlKind) -> u64 {
    DDL_LOG_COUNTER
        .with_label_values(&["sql", kind.as_str()])
        .get()
}

/// Every `tinycloud.sql/*` ability the invocation holds, plus the node's DDL
/// policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SqlAuthority {
    held: Vec<String>,
    ddl_policy: DdlPolicy,
}

impl SqlAuthority {
    pub fn new<I, S>(held: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            held: held.into_iter().map(Into::into).collect(),
            ddl_policy: DdlPolicy::default(),
        }
    }

    pub fn with_ddl_policy(mut self, policy: DdlPolicy) -> Self {
        self.ddl_policy = policy;
        self
    }

    pub fn ddl_policy(&self) -> DdlPolicy {
        self.ddl_policy
    }

    fn confers(&self, required: &str) -> bool {
        self.held.iter().any(|held| ability_matches(held, required))
    }

    /// `admin` or `*`.
    pub fn is_admin(&self) -> bool {
        self.confers(ADMIN)
    }

    /// `schema`, or `admin` / `*` through the registry.
    pub fn confers_schema(&self) -> bool {
        self.confers(SCHEMA)
    }

    /// `write`, `*` or `admin`: may change data.
    pub fn confers_data_write(&self) -> bool {
        self.is_admin() || self.confers(WRITE)
    }

    /// Holds something other than the exact `schema` tier. The exact `schema`
    /// tier is DDL-only, so a holder of nothing else cannot run data statements.
    pub fn has_non_schema_ability(&self) -> bool {
        self.held.iter().any(|held| resolve_alias(held) != SCHEMA)
    }

    /// Every ability other than `schema` is the exact read tier (`read` or its
    /// `select` alias). `sql/*` implies read but must still permit writes, so
    /// this compares the resolved URN instead of using `ability_matches`.
    pub fn is_read_tier_only(&self) -> bool {
        let mut non_schema = self
            .held
            .iter()
            .map(|held| resolve_alias(held))
            .filter(|held| *held != SCHEMA)
            .peekable();
        non_schema.peek().is_some() && non_schema.all(|held| held == READ)
    }

    /// Whether a schema-changing statement may run for this holder.
    ///
    /// `Enforce` needs a schema-conferring ability. `Log` and `Off` keep the
    /// pre-TC-1581 rule, where `write` also sufficed.
    pub fn may_change_schema(&self) -> bool {
        match self.ddl_policy {
            DdlPolicy::Enforce => self.confers_schema(),
            DdlPolicy::Log | DdlPolicy::Off => {
                self.confers_schema() || self.confers(WRITE) || self.is_admin()
            }
        }
    }

    /// The statement would be refused under `Enforce` but runs under `Log`.
    pub fn schema_change_only_by_legacy_rule(&self) -> bool {
        self.ddl_policy == DdlPolicy::Log && self.may_change_schema() && !self.confers_schema()
    }
}

impl From<&str> for SqlAuthority {
    fn from(ability: &str) -> Self {
        Self::new([ability])
    }
}

impl From<String> for SqlAuthority {
    fn from(ability: String) -> Self {
        Self::new([ability])
    }
}

impl<const N: usize> From<[&str; N]> for SqlAuthority {
    fn from(held: [&str; N]) -> Self {
        Self::new(held)
    }
}

impl From<Vec<String>> for SqlAuthority {
    fn from(held: Vec<String>) -> Self {
        Self::new(held)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(abilities: &[&str]) -> SqlAuthority {
        SqlAuthority::new(abilities.iter().copied())
    }

    #[test]
    fn schema_is_conferred_by_schema_admin_and_wildcard_only() {
        for (abilities, expected) in [
            (&["tinycloud.sql/read"][..], false),
            (&["tinycloud.sql/select"][..], false),
            (&["tinycloud.sql/write"][..], false),
            (&["tinycloud.sql/read", "tinycloud.sql/write"][..], false),
            (&["tinycloud.sql/schema"][..], true),
            (&["tinycloud.sql/write", "tinycloud.sql/schema"][..], true),
            (&["tinycloud.sql/admin"][..], true),
            (&["tinycloud.sql/*"][..], true),
            (&["tinycloud.sql/ddl"][..], false),
            (&["tinycloud.duckdb/admin"][..], false),
        ] {
            assert_eq!(held(abilities).confers_schema(), expected, "{abilities:?}");
        }
    }

    #[test]
    fn schema_does_not_confer_data_authority() {
        let schema_only = held(&["tinycloud.sql/schema"]);
        assert!(!schema_only.confers_data_write());
        assert!(!schema_only.has_non_schema_ability());
        let both = held(&["tinycloud.sql/schema", "tinycloud.sql/write"]);
        assert!(both.confers_data_write());
        assert!(both.has_non_schema_ability());
    }

    #[test]
    fn read_tier_is_exact() {
        assert!(held(&["tinycloud.sql/read"]).is_read_tier_only());
        assert!(held(&["tinycloud.sql/select"]).is_read_tier_only());
        assert!(held(&["tinycloud.sql/read", "tinycloud.sql/schema"]).is_read_tier_only());
        assert!(!held(&["tinycloud.sql/read", "tinycloud.sql/write"]).is_read_tier_only());
        assert!(!held(&["tinycloud.sql/*"]).is_read_tier_only());
        assert!(!held(&["tinycloud.sql/schema"]).is_read_tier_only());
    }

    #[test]
    fn policy_selects_who_may_change_schema() {
        let write = held(&["tinycloud.sql/write"]);
        assert!(!write
            .clone()
            .with_ddl_policy(DdlPolicy::Enforce)
            .may_change_schema());
        assert!(write
            .clone()
            .with_ddl_policy(DdlPolicy::Log)
            .may_change_schema());
        assert!(write
            .clone()
            .with_ddl_policy(DdlPolicy::Off)
            .may_change_schema());
        assert!(write
            .with_ddl_policy(DdlPolicy::Log)
            .schema_change_only_by_legacy_rule());
        let both = held(&["tinycloud.sql/write", "tinycloud.sql/schema"]);
        assert!(!both
            .with_ddl_policy(DdlPolicy::Log)
            .schema_change_only_by_legacy_rule());
        assert!(!held(&["tinycloud.sql/read"])
            .with_ddl_policy(DdlPolicy::Off)
            .may_change_schema());
    }

    #[test]
    fn policy_is_enforce_by_default_and_parses_lowercase() {
        assert_eq!(DdlPolicy::default(), DdlPolicy::Enforce);
        assert_eq!(SqlAuthority::default().ddl_policy(), DdlPolicy::Enforce);
        for (text, expected) in [
            ("\"off\"", DdlPolicy::Off),
            ("\"log\"", DdlPolicy::Log),
            ("\"enforce\"", DdlPolicy::Enforce),
        ] {
            assert_eq!(serde_json::from_str::<DdlPolicy>(text).unwrap(), expected);
        }
        assert!(serde_json::from_str::<DdlPolicy>("\"warn\"").is_err());
    }
}
