//! Delegated `tables` / `columns` / `readOnly` caveats on `tinycloud.sql/*`
//! abilities (TC-1791).
//!
//! Wire: the caveats of one ability are a list of objects; the node sees them
//! as a map keyed by entry index (`"0"`, `"1"`, ...). An entry is one of
//!
//! - empty (`{}`): no restriction,
//! - a constrained-statements profile (a `mode` key, or the nested
//!   `{"constrained-statements": {...}}` form): read by the profile rules,
//! - the delegated form: keys exactly a subset of `tables`, `columns`,
//!   `readOnly`.
//!
//! A list with a delegated entry has exactly one entry: entries are
//! alternatives, so a second entry (empty or not) would read as "or
//! unrestricted".
//!
//! Names are matched ASCII-case-insensitively and exactly otherwise (no
//! wildcards, no `table.column`). Each list has 0..=[`MAX_NAMES`] elements, each
//! element 1..=[`MAX_NAME_BYTES`] bytes of UTF-8 without a `.`, without control
//! characters and without leading or trailing whitespace.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use super::caveats::SqlCaveats;
use crate::policy_capability::sql_caveat;
use crate::types::Caveats;

/// Most elements in one `tables` or `columns` list.
pub const MAX_NAMES: usize = 256;
/// Longest element of a `tables` or `columns` list, in bytes.
pub const MAX_NAME_BYTES: usize = 128;

const FORM_KEYS: [&str; 3] = ["tables", "columns", "readOnly"];

/// How strictly a stored or presented caveat map is read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reading {
    /// A delegation being admitted: a `mode` entry beside `tables` or
    /// `columns` is refused.
    Ingress,
    /// A row already stored: a `mode` entry is a profile whatever else it
    /// carries, as it has always been read.
    Stored,
}

/// A caveat map that cannot be accepted or evaluated. `key` is the entry
/// index; `detail` is a fixed phrase that carries no caveat content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Refusal {
    pub key: String,
    pub detail: &'static str,
}

impl Refusal {
    fn new(key: &str, detail: &'static str) -> Self {
        Self {
            key: key.to_string(),
            detail,
        }
    }

    /// The reason text of the `unsupported-caveat` refusal.
    pub fn reason(&self, ability: &str) -> String {
        format!("{ability} caveat {} {}", self.key, self.detail)
    }
}

/// The restriction one ability's caveats place on SQL access.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DelegatedCaveat {
    /// Lower-cased table names; `None` = no restriction on tables.
    tables: Option<BTreeSet<String>>,
    /// Lower-cased column names; `None` = no restriction on columns.
    columns: Option<BTreeSet<String>>,
    /// `readOnly: true`; absent and `false` are the same.
    read_only: bool,
}

/// What one ability's caveat map says.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AbilityCaveats {
    /// Empty, or only empty entries.
    Unrestricted,
    /// One or more constrained-statements profiles.
    Profile,
    /// A delegated-form entry.
    Form(DelegatedCaveat),
}

fn name_refusal(value: &Value) -> Option<&'static str> {
    let Some(name) = value.as_str() else {
        return Some("has an element that is not a string");
    };
    if name.is_empty() {
        return Some("has an empty element");
    }
    if name.len() > MAX_NAME_BYTES {
        return Some("has an element that is too long");
    }
    if name.contains('.') {
        return Some("has an element with a dot");
    }
    if name.chars().any(char::is_control) {
        return Some("has an element with a control character");
    }
    if name.starts_with(char::is_whitespace) || name.ends_with(char::is_whitespace) {
        return Some("has an element with leading or trailing whitespace");
    }
    None
}

fn names(value: &Value) -> Result<BTreeSet<String>, &'static str> {
    let Some(list) = value.as_array() else {
        return Err("has a name list that is not an array");
    };
    if list.len() > MAX_NAMES {
        return Err("has a name list with too many elements");
    }
    list.iter()
        .map(|element| match name_refusal(element) {
            Some(detail) => Err(detail),
            None => Ok(fold(element.as_str().unwrap_or_default())),
        })
        .collect()
}

/// The comparison form of a table or column name.
pub fn fold(name: &str) -> String {
    name.to_ascii_lowercase()
}

impl DelegatedCaveat {
    fn from_entry(entry: &Map<String, Value>) -> Result<Self, &'static str> {
        if entry.keys().any(|key| !FORM_KEYS.contains(&key.as_str())) {
            return Err("has an unsupported key");
        }
        let read_only = match entry.get("readOnly") {
            None => false,
            Some(Value::Bool(flag)) => *flag,
            Some(_) => return Err("has a readOnly that is not a boolean"),
        };
        Ok(Self {
            tables: entry.get("tables").map(names).transpose()?,
            columns: entry.get("columns").map(names).transpose()?,
            read_only,
        })
    }

    pub fn is_unrestricted(&self) -> bool {
        self.tables.is_none() && self.columns.is_none() && !self.read_only
    }

    /// Whether `child` is at least as narrow as `self` on every axis. The
    /// reason names the axis and carries no caveat content.
    pub fn contains(&self, child: &Self) -> Result<(), &'static str> {
        fn subset(
            parent: &Option<BTreeSet<String>>,
            child: &Option<BTreeSet<String>>,
            reason: &'static str,
        ) -> Result<(), &'static str> {
            match (parent, child) {
                (None, _) => Ok(()),
                (Some(parent), Some(child)) if child.is_subset(parent) => Ok(()),
                _ => Err(reason),
            }
        }
        subset(&self.tables, &child.tables, "sql-tables-not-contained")?;
        subset(&self.columns, &child.columns, "sql-columns-not-contained")?;
        if self.read_only && !child.read_only {
            return Err("sql-read-only-not-contained");
        }
        Ok(())
    }

    /// Narrows `self` by `other`: tables and columns intersect, `readOnly` is
    /// an OR. Never widens.
    pub fn intersect(&mut self, other: &Self) {
        fn meet(mine: &mut Option<BTreeSet<String>>, theirs: &Option<BTreeSet<String>>) {
            match (mine.as_mut(), theirs) {
                (_, None) => {}
                (None, Some(theirs)) => *mine = Some(theirs.clone()),
                (Some(mine), Some(theirs)) => mine.retain(|name| theirs.contains(name)),
            }
        }
        meet(&mut self.tables, &other.tables);
        meet(&mut self.columns, &other.columns);
        self.read_only |= other.read_only;
    }

    /// The executor form: `None` when nothing is restricted. Names are the
    /// folded forms; the authorizer compares ASCII-case-insensitively.
    pub fn to_sql_caveats(&self) -> Option<SqlCaveats> {
        (!self.is_unrestricted()).then(|| SqlCaveats {
            tables: self.tables.as_ref().map(|t| t.iter().cloned().collect()),
            columns: self.columns.as_ref().map(|c| c.iter().cloned().collect()),
            statements: None,
            read_only: self.read_only.then_some(true),
        })
    }

    /// `self` narrowed by the caveats the invoker wrote into the invocation
    /// facts. The facts only narrow; their statements are carried as given.
    pub fn narrowed_by_facts(&self, facts: Option<SqlCaveats>) -> Option<SqlCaveats> {
        let Some(facts) = facts else {
            return self.to_sql_caveats();
        };
        let fact_form = Self {
            tables: facts
                .tables
                .as_ref()
                .map(|t| t.iter().map(|n| fold(n)).collect()),
            columns: facts
                .columns
                .as_ref()
                .map(|c| c.iter().map(|n| fold(n)).collect()),
            read_only: facts.read_only.unwrap_or(false),
        };
        let mut merged = self.clone();
        merged.intersect(&fact_form);
        Some(SqlCaveats {
            tables: merged.tables.map(|t| t.into_iter().collect()),
            columns: merged.columns.map(|c| c.into_iter().collect()),
            statements: facts.statements,
            read_only: merged.read_only.then_some(true),
        })
    }
}

/// Reads one ability's caveat map. Refusal at `Reading::Ingress` is the
/// `unsupported-caveat` refusal; at `Reading::Stored` it means the row cannot
/// be evaluated and the request fails closed.
pub fn classify(caveats: &Caveats, reading: Reading) -> Result<AbilityCaveats, Refusal> {
    let mut forms = Vec::new();
    let mut profiles = 0usize;
    let mut empties = 0usize;
    let mut first_empty = None;
    for (key, value) in &caveats.0 {
        let Some(entry) = value.as_object() else {
            return Err(Refusal::new(key, "is not an object"));
        };
        if entry.is_empty() {
            empties += 1;
            first_empty.get_or_insert(key);
        } else if let Some(inner) = entry.get("constrained-statements") {
            if entry.len() != 1 {
                return Err(Refusal::new(key, "has keys beside constrained-statements"));
            }
            if sql_caveat::parse(inner).is_err() {
                return Err(Refusal::new(key, "is not a constrained-statements profile"));
            }
            profiles += 1;
        } else if entry.contains_key("mode") {
            if reading == Reading::Ingress
                && (entry.contains_key("tables") || entry.contains_key("columns"))
            {
                return Err(Refusal::new(
                    key,
                    "mixes a constrained-statements profile with tables or columns",
                ));
            }
            if sql_caveat::parse(value).is_err() {
                return Err(Refusal::new(key, "is not a constrained-statements profile"));
            }
            profiles += 1;
        } else {
            let form =
                DelegatedCaveat::from_entry(entry).map_err(|detail| Refusal::new(key, detail))?;
            forms.push((key, form));
        }
    }
    if let Some((key, form)) = forms.first() {
        if forms.len() + profiles + empties != 1 {
            return Err(Refusal::new(key, "is one of several entries"));
        }
        return Ok(AbilityCaveats::Form(form.clone()));
    }
    if profiles > 0 {
        return match first_empty {
            // An empty entry beside a profile is not a profile.
            Some(key) => Err(Refusal::new(key, "is not a constrained-statements profile")),
            None => Ok(AbilityCaveats::Profile),
        };
    }
    Ok(AbilityCaveats::Unrestricted)
}

/// The delegated restriction a stored chain places on one invocation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ChainCaveat {
    /// Intersection of the delegated forms on the chain.
    pub form: DelegatedCaveat,
    /// At least one hop on the chain carries a delegated form.
    pub has_form: bool,
    /// At least one hop on the chain carries a constrained-statements profile.
    pub has_profile: bool,
}

/// Why a chain's caveats could not be evaluated. Every variant refuses the
/// request.
#[derive(Debug)]
pub enum ChainCaveatError {
    /// A hop's caveat does not parse, or a hop's row is missing.
    Unevaluable,
    /// The chain is longer than the traversal bound.
    LimitExceeded,
    Db(sea_orm::DbErr),
}

/// Intersects the delegated forms of every row that grants one of the invoked
/// capabilities. A row that does not match carries no weight; a matching row
/// without a restriction contributes nothing; a matching row whose caveat does
/// not parse fails the whole evaluation.
pub fn chain_caveat_of_rows<'a>(
    rows: impl IntoIterator<Item = &'a crate::models::abilities::Model>,
    invoked: &[crate::util::Capability],
) -> Result<ChainCaveat, ChainCaveatError> {
    let mut chain = ChainCaveat::default();
    for row in rows {
        let matches = invoked.iter().any(|capability| {
            capability.resource.extends(&row.resource)
                && crate::policy_capability::ability_matches(
                    row.ability.as_ref().as_ref(),
                    capability.ability.as_ref().as_ref(),
                )
        });
        if !matches {
            continue;
        }
        match classify(&row.caveats, Reading::Stored) {
            Err(_) => return Err(ChainCaveatError::Unevaluable),
            Ok(AbilityCaveats::Unrestricted) => {}
            Ok(AbilityCaveats::Profile) => chain.has_profile = true,
            Ok(AbilityCaveats::Form(form)) => {
                chain.form.intersect(&form);
                chain.has_form = true;
            }
        }
    }
    Ok(chain)
}

/// The chain caveat of an invocation that cites `parents`: every stored
/// delegation reachable from them, however it was admitted.
pub async fn chain_caveat<C: sea_orm::ConnectionTrait>(
    db: &C,
    parents: &[crate::hash::Hash],
    invoked: &[crate::util::Capability],
) -> Result<ChainCaveat, ChainCaveatError> {
    use crate::auth_graph::{AuthGraphSnapshot, ChainTraversalError};
    let graph = AuthGraphSnapshot::load(db, parents)
        .await
        .map_err(|error| match error {
            ChainTraversalError::Db(error) => ChainCaveatError::Db(error),
            ChainTraversalError::LimitExceeded => ChainCaveatError::LimitExceeded,
        })?;
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    for root in parents {
        for id in graph.chain_ids_from(root) {
            if !seen.insert(id) {
                continue;
            }
            if graph.delegation(&id).is_none() {
                return Err(ChainCaveatError::Unevaluable);
            }
            rows.extend(graph.abilities(&id));
        }
    }
    chain_caveat_of_rows(rows, invoked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::delegation::unsupported_sql_caveat_at_ingress;
    use serde_json::json;

    const SQL: &str = "tinycloud.sql/read";

    /// What the node sees for one ability's caveat list: the capability
    /// parser collapses `[{}]` to no caveat and keeps every other list as
    /// entries keyed by index (pinned by `util::tests`).
    fn wire(list: Value) -> Caveats {
        let entries = list.as_array().expect("a list");
        if entries.len() == 1 && entries[0] == json!({}) {
            return Caveats::default();
        }
        Caveats(
            entries
                .iter()
                .enumerate()
                .map(|(index, entry)| (index.to_string(), entry.clone()))
                .collect(),
        )
    }

    fn ingress(list: Value) -> Option<String> {
        unsupported_sql_caveat_at_ingress(SQL, &wire(list), true)
    }

    fn form(list: Value) -> DelegatedCaveat {
        match classify(&wire(list), Reading::Ingress) {
            Ok(AbilityCaveats::Form(form)) => form,
            other => panic!("not a delegated form: {other:?}"),
        }
    }

    fn profile() -> Value {
        json!({"mode": "constrained-statements", "readOnly": true,
               "statements": [{"name": "get", "sql": "SELECT 1"}]})
    }

    fn names(count: usize) -> Vec<String> {
        (0..count).map(|i| format!("t{i}")).collect()
    }

    #[test]
    fn valid_forms_are_accepted() {
        for list in [
            json!([]),                                                                   // V1
            json!([{}]),                                                                 // V2
            json!([{"tables": ["Notes"]}]),                                              // V3
            json!([{"columns": ["body", "id"]}]),                                        // V4
            json!([{"readOnly": true}]),                                                 // V5
            json!([{"tables": ["Notes", "t2"], "columns": ["body"], "readOnly": true}]), // V6
            json!([{"readOnly": false}]),                                                // V7
            json!([{"tables": []}]),                                                     // V8
            json!([{"tables": ["NOTES"]}]),                                              // V9
            json!([profile()]),                                // V10 (mode form)
            json!([{"constrained-statements": profile()}]),    // V10 (nested)
            json!([{"tables": names(256)}]),                   // V11
            json!([{}, {}]),                                   // V12
            json!([{"tables": ["a".repeat(MAX_NAME_BYTES)]}]), // longest element
        ] {
            assert_eq!(ingress(list.clone()), None, "{list}");
        }
        // V9: equal after folding.
        assert_eq!(
            form(json!([{"tables": ["NOTES"]}])),
            form(json!([{"tables": ["Notes"]}]))
        );
        // V8: allows no table, which is not the absence of the key.
        assert_ne!(form(json!([{"tables": []}])), DelegatedCaveat::default());
        // V7: explicit false is the same as absent.
        assert!(form(json!([{"readOnly": false}])).is_unrestricted());
        // V12: two empty entries restrict nothing.
        assert_eq!(
            classify(&wire(json!([{}, {}])), Reading::Stored),
            Ok(AbilityCaveats::Unrestricted)
        );
    }

    #[test]
    fn refused_forms_are_unsupported_caveats() {
        let long = "a".repeat(MAX_NAME_BYTES + 1);
        for list in [
            json!([{"tabels": ["a"]}]),                    // R1
            json!([{"tables": ["a"], "extra": 1}]),        // R1
            json!([{"tables": "a"}]),                      // R2
            json!([{"columns": "a"}]),                     // R2
            json!([{"readOnly": "true"}]),                 // R2
            json!([{"readOnly": 1}]),                      // R2
            json!([{"readOnly": null}]),                   // R2
            json!([{"tables": [1]}]),                      // R2
            json!([{"tables": [null]}]),                   // R2
            json!([{"tables": [["a"]]}]),                  // R2
            json!([{"tables": [""]}]),                     // R3
            json!([{"tables": names(257)}]),               // R4
            json!([{"columns": names(257)}]),              // R4
            json!([{"tables": ["Notes.body"]}]),           // R5
            json!([{"columns": ["Notes.body"]}]),          // R5
            json!([{"tables": ["a"]}, {"tables": ["b"]}]), // R6
            json!([{"tables": ["a"]}, {}]),                // R6
            json!([{}, {"readOnly": true}]),               // R6
            json!([{"tables": ["a"]}, profile()]),         // R6
            json!([{"mode": "constrained-statements", "readOnly": true, "tables": ["a"],
                    "statements": []}]), // R7
            json!([{"mode": "constrained-statements", "readOnly": true, "columns": ["a"],
                    "statements": []}]), // R7
            json!([1]),                                    // R8
            json!(["x"]),                                  // R8
            json!([null]),                                 // R8
            json!([[]]),                                   // R8
            json!([{"tables": [" a"]}]),                   // R10
            json!([{"tables": ["a "]}]),                   // R10
            json!([{"columns": ["a\n"]}]),                 // R10
            json!([{"columns": ["a\u{0}b"]}]),             // R10
            json!([{"tables": [long]}]),                   // longer than the cap
            json!([profile(), {}]),                        // a profile beside an empty entry
        ] {
            let reason = ingress(list.clone());
            assert!(
                reason
                    .as_deref()
                    .is_some_and(|r| r.starts_with("tinycloud.sql/read caveat ")),
                "{list} -> {reason:?}"
            );
        }
    }

    #[test]
    fn a_refusal_never_carries_a_caveat_value() {
        let reason = ingress(json!([{"tables": ["SecretTableName."]}])).unwrap();
        assert!(!reason.contains("SecretTableName"), "{reason}");
    }

    #[test]
    fn only_ascii_letters_fold() {
        // The Kelvin sign is accepted as a name and is not `k`.
        assert_eq!(ingress(json!([{"tables": ["\u{212A}x"]}])), None);
        assert_ne!(
            form(json!([{"tables": ["\u{212A}x"]}])),
            form(json!([{"tables": ["kx"]}]))
        );
        assert_eq!(fold("\u{212A}X"), "\u{212A}x");
        assert_eq!(fold("KX"), "kx");
    }

    #[test]
    fn with_the_setting_off_only_empty_caveats_and_profiles_are_accepted() {
        let off = |list: Value| unsupported_sql_caveat_at_ingress(SQL, &wire(list), false);
        for list in [
            json!([{"tables": ["Notes"]}]),
            json!([{"columns": ["body"]}]),
            json!([{"readOnly": true}]),
            json!([{"tables": []}]),
            json!([{}, {}]),
        ] {
            let reason = off(list.clone()).unwrap_or_else(|| panic!("{list} accepted"));
            assert!(
                reason.ends_with("is not a constrained-statements profile"),
                "{reason}"
            );
        }
        for list in [json!([]), json!([{}]), json!([profile()])] {
            assert_eq!(off(list), None);
        }
        // With the setting off a profile entry keeps the keys beside `mode`.
        assert_eq!(
            off(json!([{"mode": "constrained-statements", "readOnly": true,
                         "tables": ["a"], "statements": []}])),
            None
        );
        // DuckDB takes empty caveats only, with the setting on or off.
        for flag in [false, true] {
            let refused = unsupported_sql_caveat_at_ingress(
                "tinycloud.duckdb/read",
                &wire(json!([{"tables": ["a"]}])),
                flag,
            );
            assert!(refused.is_some_and(|r| r.contains("accepts empty caveats only")));
            assert_eq!(
                unsupported_sql_caveat_at_ingress(
                    "tinycloud.duckdb/read",
                    &wire(json!([{}])),
                    flag
                ),
                None
            );
            assert!(unsupported_sql_caveat_at_ingress(
                "tinycloud.duckdb/read",
                &wire(json!([profile()])),
                flag
            )
            .is_some());
        }
    }

    #[test]
    fn a_stored_profile_entry_ignores_keys_beside_mode() {
        // A profile entry carrying `tables` beside `mode` is a profile; the
        // setting-on admission check refuses the mixture.
        let stored = wire(json!([{"mode": "constrained-statements", "readOnly": true,
                                   "tables": ["a"], "statements": []}]));
        assert_eq!(
            classify(&stored, Reading::Stored),
            Ok(AbilityCaveats::Profile)
        );
        assert!(classify(&stored, Reading::Ingress).is_err());
    }

    #[test]
    fn containment_is_per_axis_and_folds_case() {
        let ok = |parent: Value, child: Value| form(parent).contains(&form(child));
        // S1
        assert_eq!(
            ok(
                json!([{"tables": ["Notes", "t2"]}]),
                json!([{"tables": ["Notes"]}])
            ),
            Ok(())
        );
        // S2
        assert!(ok(
            json!([{"tables": ["Notes"]}]),
            json!([{"tables": ["Notes", "plain"]}])
        )
        .is_err());
        // S3: an absent parent axis is unrestricted
        assert_eq!(
            ok(json!([{"readOnly": false}]), json!([{"tables": ["Notes"]}])),
            Ok(())
        );
        // S4
        assert!(ok(json!([{"readOnly": true}]), json!([{"readOnly": false}])).is_err());
        assert!(ok(json!([{"readOnly": true}]), json!([{"tables": ["a"]}])).is_err());
        assert_eq!(
            ok(json!([{"readOnly": false}]), json!([{"readOnly": true}])),
            Ok(())
        );
        assert_eq!(
            ok(
                json!([{"tables": ["a"]}]),
                json!([{"tables": ["a"], "readOnly": true}])
            ),
            Ok(())
        );
        // S5
        assert!(ok(
            json!([{"columns": ["id"]}]),
            json!([{"columns": ["id", "body"]}])
        )
        .is_err());
        assert_eq!(
            ok(json!([{"columns": ["id"]}]), json!([{"columns": ["id"]}])),
            Ok(())
        );
        // S6: both sides fold
        assert_eq!(
            ok(
                json!([{"tables": ["notes"]}]),
                json!([{"tables": ["NOTES"]}])
            ),
            Ok(())
        );
        assert_eq!(
            ok(
                json!([{"tables": ["NOTES"]}]),
                json!([{"tables": ["notes"]}])
            ),
            Ok(())
        );
        // S7: a child that drops a restricted axis widens
        assert!(ok(json!([{"tables": ["a"]}]), json!([{"readOnly": true}])).is_err());
        assert!(ok(json!([{"columns": ["a"]}]), json!([{"tables": ["a"]}])).is_err());
        // S8
        assert!(ok(json!([{"tables": ["Notes"]}]), json!([{"readOnly": true}])).is_err());
        // an empty table list is a restriction, narrower than any non-empty list
        assert_eq!(
            ok(json!([{"tables": ["a"]}]), json!([{"tables": []}])),
            Ok(())
        );
        assert!(ok(json!([{"tables": []}]), json!([{"tables": ["a"]}])).is_err());
    }

    fn row(ability: &str, resource: &str, caveats: Caveats) -> crate::models::abilities::Model {
        crate::models::abilities::Model {
            delegation: crate::hash::hash(ability.as_bytes()),
            resource: resource.parse().expect("a resource"),
            ability: ability.to_string().try_into().expect("an ability"),
            caveats,
        }
    }

    const DB: &str =
        "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:default/sql/db";

    fn invoked(ability: &str) -> Vec<crate::util::Capability> {
        vec![crate::util::Capability {
            resource: DB.parse().expect("a resource"),
            ability: ability.to_string().try_into().expect("an ability"),
            caveats: Caveats::default(),
        }]
    }

    fn effective(
        rows: &[crate::models::abilities::Model],
    ) -> Result<ChainCaveat, ChainCaveatError> {
        chain_caveat_of_rows(rows, &invoked(SQL))
    }

    #[test]
    fn the_effective_caveat_is_the_intersection_over_the_chain() {
        let hop = |list: Value| row("tinycloud.sql/*", DB, wire(list));
        // E1
        let chain = effective(&[
            hop(json!([{"tables": ["Notes", "t2"]}])),
            hop(json!([{"tables": ["Notes"]}])),
        ])
        .unwrap();
        assert_eq!(chain.form, form(json!([{"tables": ["Notes"]}])));
        assert!(chain.has_form && !chain.has_profile);
        // E2: a hop without a caveat contributes nothing; so does a hop that
        // grants another ability or another resource.
        let chain = effective(&[
            hop(json!([{}])),
            hop(json!([{"tables": ["Notes"]}])),
            row("tinycloud.sql/admin", DB, wire(json!([{"tables": ["other"]}]))),
            row("tinycloud.kv/get", DB, wire(json!([{"tables": ["other"]}]))),
            row(
                "tinycloud.sql/*",
                "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:default/sql/elsewhere",
                wire(json!([{"tables": ["other"]}])),
            ),
        ])
        .unwrap();
        assert_eq!(chain.form, form(json!([{"tables": ["Notes"]}])));
        // E3: readOnly is an OR over the hops
        let chain = effective(&[
            hop(json!([{"readOnly": true}])),
            hop(json!([{"tables": ["a"], "readOnly": false}])),
        ])
        .unwrap();
        assert_eq!(
            chain.form,
            form(json!([{"tables": ["a"], "readOnly": true}]))
        );
        // E4: a hop wider than its parent can only be narrowed
        let chain = effective(&[
            hop(json!([{"tables": ["Notes"]}])),
            hop(json!([{"tables": ["Notes", "plain"]}])),
            hop(json!([{"tables": ["plain", "t2"]}])),
        ])
        .unwrap();
        assert_eq!(chain.form, form(json!([{"tables": []}])));
        let chain = effective(&[
            hop(json!([{"tables": ["Notes"]}])),
            hop(json!([{"tables": ["Notes", "plain"]}])),
            hop(json!([{}])),
        ])
        .unwrap();
        assert_eq!(chain.form, form(json!([{"tables": ["Notes"]}])));
        // A chain with no restriction.
        let chain = effective(&[hop(json!([{}])), hop(json!([{}, {}]))]).unwrap();
        assert_eq!(chain, ChainCaveat::default());
    }

    #[test]
    fn an_unparseable_hop_anywhere_fails_the_chain() {
        let hop = |list: Value| row("tinycloud.sql/*", DB, wire(list));
        for bad in [
            json!([{"tables": "Notes"}]),
            json!([{"tabels": ["a"]}]),
            json!([{"tables": ["a"]}, {"tables": ["b"]}]),
            json!(["x"]),
        ] {
            for rows in [
                vec![hop(bad.clone()), hop(json!([{"tables": ["Notes"]}]))],
                vec![hop(json!([{"tables": ["Notes"]}])), hop(bad.clone())],
            ] {
                assert!(
                    matches!(effective(&rows), Err(ChainCaveatError::Unevaluable)),
                    "{bad}"
                );
            }
        }
        // An unparseable row for an ability the invocation does not hold is
        // not evaluated.
        assert!(effective(&[
            row("tinycloud.kv/get", DB, wire(json!(["x"]))),
            hop(json!([{"tables": ["Notes"]}]))
        ])
        .is_ok());
    }

    #[test]
    fn a_profile_on_the_chain_is_reported_beside_a_form() {
        let hop = |list: Value| row("tinycloud.sql/*", DB, wire(list));
        let chain = effective(&[hop(json!([profile()])), hop(json!([{"tables": ["a"]}]))]).unwrap();
        assert!(chain.has_profile && chain.has_form);
    }

    #[test]
    fn the_invocation_facts_only_narrow() {
        // E6
        let chain = form(json!([{"tables": ["Notes"]}]));
        let facts = SqlCaveats {
            tables: Some(vec!["notes".into(), "Plain".into()]),
            ..SqlCaveats::default()
        };
        let merged = chain.narrowed_by_facts(Some(facts)).unwrap();
        assert_eq!(merged.tables, Some(vec!["notes".to_string()]));
        // Facts cannot lift a restriction on another axis, and a chain with
        // no restriction takes the facts as they are.
        let facts = SqlCaveats {
            columns: Some(vec!["Body".into()]),
            read_only: Some(true),
            ..SqlCaveats::default()
        };
        let merged = chain.narrowed_by_facts(Some(facts.clone())).unwrap();
        assert_eq!(merged.tables, Some(vec!["notes".to_string()]));
        assert_eq!(merged.columns, Some(vec!["body".to_string()]));
        assert_eq!(merged.read_only, Some(true));
        let merged = DelegatedCaveat::default()
            .narrowed_by_facts(Some(facts))
            .unwrap();
        assert_eq!(merged.tables, None);
        // Nothing anywhere: no caveat at all.
        assert!(DelegatedCaveat::default().narrowed_by_facts(None).is_none());
        // `readOnly: false` in the facts does not lift a chain's `readOnly`.
        let read_only = form(json!([{"readOnly": true}]));
        let merged = read_only
            .narrowed_by_facts(Some(SqlCaveats {
                read_only: Some(false),
                ..SqlCaveats::default()
            }))
            .unwrap();
        assert_eq!(merged.read_only, Some(true));
    }
}
