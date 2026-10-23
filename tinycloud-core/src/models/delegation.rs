use crate::encryption::ColumnEncryption;
use crate::encryption_network::key_id;
use crate::hash::Hash;
use crate::models::did_resolution::{verify_ucan_signature, UcanVerifyError};
use crate::policy_capability::sql_caveat;
use crate::types::{Ability, Caveats, Facts, Resource};
use crate::util::DelegationMode;
use crate::{events::Delegation, models::*, relationships::*, util};
use sea_orm::ActiveValue::Set;
use sea_orm::{
    entity::prelude::*,
    sea_query::{Alias, CommonTableExpression, Expr, OnConflict, Query, WithClause},
    ConnectionTrait, DbBackend, QueryTrait,
};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use tinycloud_auth::{authorization::TinyCloudDelegation, identity::did_principal_matches};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "delegation")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub id: Hash,

    pub delegator: String,
    pub delegatee: String,
    pub expiry: Option<OffsetDateTime>,
    pub issued_at: Option<OffsetDateTime>,
    pub not_before: Option<OffsetDateTime>,
    pub facts: Option<Facts>,
    pub serialization: Vec<u8>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    // inverse relation, delegations belong to delegators
    #[sea_orm(
        belongs_to = "actor::Entity",
        from = "Column::Delegator",
        to = "actor::Column::Id"
    )]
    Delegator,
    #[sea_orm(
        belongs_to = "actor::Entity",
        from = "Column::Delegatee",
        to = "actor::Column::Id"
    )]
    Delegatee,
    #[sea_orm(has_many = "revocation::Entity")]
    Revocation,
    #[sea_orm(has_many = "abilities::Entity")]
    Abilities,
    #[sea_orm(has_many = "parent_delegations::Entity")]
    Parents,
}

impl Related<actor::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Delegator.def()
    }
}

impl Related<revocation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Revocation.def()
    }
}

impl Related<abilities::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Abilities.def()
    }
}

impl Related<parent_delegations::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Parents.def()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Delegator;

impl Linked for Delegator {
    type FromEntity = Entity;

    type ToEntity = actor::Entity;

    fn link(&self) -> Vec<RelationDef> {
        vec![Relation::Delegator.def()]
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Delegatee;

impl Linked for Delegatee {
    type FromEntity = Entity;

    type ToEntity = actor::Entity;

    fn link(&self) -> Vec<RelationDef> {
        vec![Relation::Delegatee.def()]
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Db(#[from] DbErr),
    #[error(transparent)]
    InvalidDelegation(#[from] DelegationError),
}

/// Outcome of a single delegation persistence attempt inside a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationRegistration {
    /// The exact serialization was inserted now; dependent rows (actors,
    /// abilities, parents) were also written.
    New(Hash),
    /// The exact serialization hash already existed; no rows were duplicated.
    Existing(Hash),
}

impl DelegationRegistration {
    pub fn hash(self) -> Hash {
        match self {
            DelegationRegistration::New(h) | DelegationRegistration::Existing(h) => h,
        }
    }

    pub fn is_new(self) -> bool {
        matches!(self, DelegationRegistration::New(_))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DelegationError {
    #[error("Delegation expired or not yet valid")]
    InvalidTime,
    #[error("Failed to verify signature")]
    InvalidSignature,
    #[error("did_method_disabled: DID method `{0}` is not resolvable on this node")]
    UnsupportedDidMethod(String),
    #[error("did_url_query_rejected: issuer DID URL must not carry a query")]
    DidUrlQueryRejected,
    #[error("Unauthorized Delegator: {0}")]
    UnauthorizedDelegator(String),
    #[error("Unauthorized Capability: {0}, {1}")]
    UnauthorizedCapability(Box<Resource>, Ability),
    #[error("Cannot find parent delegation")]
    MissingParents,
    #[error("Child delegation expiry exceeds parent expiry")]
    ExpiryExceedsParent,
    #[error("Child delegation not_before precedes parent not_before")]
    NotBeforePrecedesParent,
    /// W1: parent delegation is terminal — children cannot redelegate.
    /// Maps to `terminal-parent-cannot-redelegate` in the W0 vectors.
    #[error("terminal-parent-cannot-redelegate")]
    TerminalParentCannotRedelegate,
    #[error("delegation-parent-revoked: {0}")]
    ParentRevoked(String),
    #[error("delegation-ancestor-revoked: ancestor={ancestor_cid} parent={parent_cid}")]
    AncestorRevoked {
        ancestor_cid: String,
        parent_cid: String,
    },
    #[error("delegation-chain-traversal-limit-exceeded")]
    ChainTraversalLimitExceeded,
    #[error("policy-root-requires-conjunctive-session")]
    PolicyRootRequiresConjunctiveSession,
    #[error("policy-descendant-fact-invalid")]
    PolicyDescendantFactInvalid,
    /// W1: child caveats are not a subset of the parent's caveats — the
    /// child dropped, widened, or replaced a constrained-statements caveat
    /// the parent carried (audit P0 finding 1). Maps to the spec rejection
    /// code from `sql-constrained-statement-caveat.md` containment.
    #[error("child-caveats-not-subset-of-parent: {0}")]
    CaveatsNotContained(String),
    /// TC-1791: a SQL or DuckDB capability carries a caveat that is neither
    /// empty nor a constrained-statements profile. Only those two forms are
    /// accepted.
    #[error("unsupported-caveat: {0}")]
    UnsupportedCaveat(String),
    /// Key deletion is never delegated. Code: `key-delete-not-delegable`.
    #[error("key-delete-not-delegable")]
    KeyDeleteNotDelegable,
    /// Named-key resources (keys and key prefixes) are served only while the
    /// node's named-keys setting is on.
    #[error("named_keys_unavailable: named keys are not enabled on this node")]
    NamedKeysUnavailable,
}

/// Verify, validate, and register a delegation inside the caller's transaction.
///
/// Returns `New` when the exact serialization was inserted (and actors,
/// abilities, and parents written). Returns `Existing` when the hash was
/// already present; no dependent rows are duplicated in that case.
#[cfg(test)]
pub(crate) async fn process<C: ConnectionTrait>(
    db: &C,
    delegation: &Delegation,
    encryption: Option<&ColumnEncryption>,
) -> Result<DelegationRegistration, Error> {
    process_with(db, delegation, encryption, false, true).await
}

/// As `process`; with `delegated_sql_caveats` a SQL capability may carry the
/// delegated `tables` / `columns` / `readOnly` caveat form (TC-1791). Without
/// `named_keys` a capability on a key or key prefix is refused.
pub(crate) async fn process_with<C: ConnectionTrait>(
    db: &C,
    delegation: &Delegation,
    encryption: Option<&ColumnEncryption>,
    delegated_sql_caveats: bool,
    named_keys: bool,
) -> Result<DelegationRegistration, Error> {
    verify(&delegation.0.delegation).await?;
    for space in delegation.0.spaces() {
        crate::request_telemetry::observe_space(space);
    }
    validate_with(db, &delegation.0, delegated_sql_caveats, named_keys).await?;
    save(db, delegation.0.clone(), delegation.1.clone(), encryption).await
}

// verify signatures and time
async fn verify(delegation: &TinyCloudDelegation) -> Result<(), Error> {
    match delegation {
        TinyCloudDelegation::Ucan(ref ucan) => {
            verify_ucan_signature(ucan)
                .await
                .map_err(|error| match error {
                    UcanVerifyError::MethodDisabled { method } => {
                        DelegationError::UnsupportedDidMethod(method)
                    }
                    UcanVerifyError::QueryRejected => DelegationError::DidUrlQueryRejected,
                    UcanVerifyError::Timeout | UcanVerifyError::Invalid => {
                        DelegationError::InvalidSignature
                    }
                })?;
            ucan.payload()
                .validate_time(None)
                .map_err(|_| DelegationError::InvalidTime)?;
        }
        TinyCloudDelegation::Cacao(ref cacao) => {
            cacao
                .verify()
                .await
                .map_err(|_| DelegationError::InvalidSignature)?;
            if !cacao.payload().valid_now() {
                return Err(DelegationError::InvalidTime.into());
            }
        }
    };
    Ok(())
}

// TC-1791: refusal reason for a SQL or DuckDB capability whose caveats are
// not accepted. SQL accepts empty caveats or, per entry, a
// constrained-statements profile. DuckDB accepts empty caveats only.
pub(crate) fn unsupported_sql_caveat(
    ability: &str,
    caveats: &crate::types::Caveats,
) -> Option<String> {
    if ability.starts_with("tinycloud.duckdb/") {
        return caveats.0.keys().next().map(|key| {
            format!("{ability} caveat {key} is not accepted; {ability} accepts empty caveats only")
        });
    }
    if !ability.starts_with("tinycloud.sql/") {
        return None;
    }
    caveats.0.iter().find_map(|(key, value)| {
        let profile = match value.as_object() {
            Some(map) if map.contains_key("constrained-statements") => {
                if map.len() != 1 {
                    return Some(format!(
                        "{ability} caveat {key} has keys beside constrained-statements"
                    ));
                }
                &map["constrained-statements"]
            }
            _ => value,
        };
        sql_caveat::parse(profile)
            .err()
            .map(|_| format!("{ability} caveat {key} is not a constrained-statements profile"))
    })
}

/// Reason a SQL or DuckDB capability's caveats are refused at admission. With
/// `delegated_sql_caveats` a SQL capability may also carry the delegated
/// `tables` / `columns` / `readOnly` form; DuckDB takes empty caveats only.
pub(crate) fn unsupported_sql_caveat_at_ingress(
    ability: &str,
    caveats: &crate::types::Caveats,
    delegated_sql_caveats: bool,
) -> Option<String> {
    use crate::sql::delegated_caveats::{classify, Reading};
    if delegated_sql_caveats && ability.starts_with("tinycloud.sql/") {
        return classify(caveats, Reading::Ingress)
            .err()
            .map(|refusal| refusal.reason(ability));
    }
    unsupported_sql_caveat(ability, caveats)
}

/// As [`unsupported_sql_caveat`], for a row already stored. With
/// `delegated_sql_caveats` the delegated form is read as well.
pub(crate) fn unsupported_stored_sql_caveat(
    ability: &str,
    caveats: &crate::types::Caveats,
    delegated_sql_caveats: bool,
) -> Option<String> {
    use crate::sql::delegated_caveats::{classify, Reading};
    if delegated_sql_caveats && ability.starts_with("tinycloud.sql/") {
        return classify(caveats, Reading::Stored)
            .err()
            .map(|refusal| refusal.reason(ability));
    }
    unsupported_sql_caveat(ability, caveats)
}

fn check_sql_caveats_supported(
    cap: &util::Capability,
    delegated_sql_caveats: bool,
) -> Result<(), Error> {
    match unsupported_sql_caveat_at_ingress(
        cap.ability.as_ref().as_ref(),
        &cap.caveats,
        delegated_sql_caveats,
    ) {
        Some(reason) => Err(DelegationError::UnsupportedCaveat(reason).into()),
        None => Ok(()),
    }
}

// verify parenthood and authorization
#[cfg(test)]
async fn validate<C: ConnectionTrait>(
    db: &C,
    delegation: &util::DelegationInfo,
) -> Result<(), Error> {
    validate_with(db, delegation, false, true).await
}

async fn validate_with<C: ConnectionTrait>(
    db: &C,
    delegation: &util::DelegationInfo,
    delegated_sql_caveats: bool,
    named_keys: bool,
) -> Result<(), Error> {
    // Without named keys, a capability on a key or key prefix is refused for
    // every delegation, before the root-authority filter, so a delegation
    // issued by the key's owner is covered too.
    if !named_keys
        && delegation
            .capabilities
            .iter()
            .any(|cap| cap.resource.is_named_key())
    {
        return Err(DelegationError::NamedKeysUnavailable.into());
    }
    // TC-1791: SQL and DuckDB caveats are checked for every delegation,
    // before the root-authority filter.
    for cap in &delegation.capabilities {
        check_sql_caveats_supported(cap, delegated_sql_caveats)?;
    }
    // Key deletion is never delegated, including by the key's owner.
    if delegation.capabilities.iter().any(|cap| {
        crate::policy_capability::ability_matches(
            &cap.ability.to_string(),
            "tinycloud.encryption/key.delete",
        )
    }) {
        return Err(DelegationError::KeyDeleteNotDelegable.into());
    }

    // get caps which rely on delegated caps
    let dependant_caps: Vec<_> = delegation
        .capabilities
        .iter()
        .filter(|c| {
            // remove caps for which the delegator is the root authority
            !is_root_authority(c, &delegation.delegator)
        })
        .collect();

    match (dependant_caps.is_empty(), delegation.parents.is_empty()) {
        // no dependant caps, no parents needed, must be valid
        (true, _) => Ok(()),
        // Policy roots are owner-signed control-plane roots.  They are
        // admitted into the ordinary graph during policy registration, but
        // they are never a usable grant on their own: the route gate rejects
        // public root imports and policy-session validation requires the
        // ordered sibling pair.  Keeping the graph row here is what lets the
        // ordinary transaction validate an S0's proof CIDs.
        (false, true) if is_policy_root(&delegation.delegation) => Ok(()),
        // An owner may grant revocation of one exact stored delegation that
        // targets their space, without holding the target's signed bytes:
        // every non-root capability must be such an exact-CID revoke grant.
        // The target's delegatee or delegator alone cannot issue one.
        (false, true) => {
            for cap in &dependant_caps {
                if !revocation::owner_controls_target(db, &delegation.delegator, cap).await? {
                    return Err(DelegationError::MissingParents.into());
                }
            }
            Ok(())
        }
        // dependant caps, parents, check parents
        (false, false) => {
            // Policy-session UCANs intentionally carry two sibling roots.  The
            // signed profile selects conjunctive semantics; using the normal
            // delegatee filter here would either drop the policy root or make
            // a later resolver fall back to any-parent authorization.
            let policy_session = is_policy_session(&delegation.delegation);
            // Resolve in the signed proof order.  A set-based query is not
            // sufficient here: database row order must never become the
            // authority for the ordered policy/enforcer conjunction.
            let mut all_parents = Vec::with_capacity(delegation.parents.len());
            for parent_cid in &delegation.parents {
                let Some(parent) = Entity::find_by_id(Hash::from(*parent_cid)).one(db).await?
                else {
                    return Err(DelegationError::MissingParents.into());
                };
                if !policy_session && parent.delegatee != delegation.delegator {
                    return Err(DelegationError::UnauthorizedDelegator(
                        delegation.delegator.clone(),
                    )
                    .into());
                }
                all_parents.push(parent);
            }

            // Every signed proof must resolve.  This is the security boundary
            // that prevents an injected, reordered, or missing sibling from
            // collapsing AND into ordinary any-parent behavior.
            if all_parents.is_empty() {
                return Err(DelegationError::MissingParents.into());
            }

            // A revoked grant cannot authorize new descendants. Check both
            // the directly cited parents and their transitive ancestors on
            // every registration so revocation takes effect immediately.
            for parent in &all_parents {
                ensure_parent_active(db, &parent.id).await?;
            }

            let policy_root_parent = all_parents.iter().any(|parent| {
                parent
                    .facts
                    .as_ref()
                    .is_some_and(|facts| facts.0.contains_key(POLICY_ROOT_FACT_KEY))
            });
            if policy_root_parent && !policy_session {
                return Err(DelegationError::PolicyRootRequiresConjunctiveSession.into());
            }
            if let Some(parent) = all_parents.iter().find(|parent| {
                parent
                    .facts
                    .as_ref()
                    .is_some_and(|facts| facts.0.contains_key(POLICY_SESSION_FACT_KEY))
            }) {
                if let Err(error) = validate_policy_descendant(delegation, parent) {
                    let error = match error {
                        PolicyDescendantError::InvalidFact => {
                            DelegationError::PolicyDescendantFactInvalid
                        }
                        PolicyDescendantError::UnauthorizedDelegator => {
                            DelegationError::UnauthorizedDelegator(delegation.delegator.clone())
                        }
                        PolicyDescendantError::ExpiryExceedsParent => {
                            DelegationError::ExpiryExceedsParent
                        }
                        PolicyDescendantError::NotBeforePrecedesParent => {
                            DelegationError::NotBeforePrecedesParent
                        }
                    };
                    return Err(error.into());
                }
            }

            // W1 (B): reject any chain that cites a terminal parent. The
            // marker is persisted on the parent row's `facts` column at
            // save time and is signed-into the parent's UCAN payload, so a
            // cooperating holder cannot strip it after the fact.
            for p in &all_parents {
                if parent_is_terminal(p) {
                    return Err(DelegationError::TerminalParentCannotRedelegate.into());
                }
            }

            // Check time constraints and track failures
            let mut expiry_failed = false;
            let mut not_before_failed = false;

            let parents: Vec<_> = all_parents
                .into_iter()
                .filter(|p| {
                    // valid time bounds: child's validity must be within parent's validity
                    // expiry: child must expire at or before parent (None = no expiry)
                    let expiry_valid = match (&p.expiry, &delegation.expiry) {
                        (None, _) => true,        // parent never expires, any child expiry is valid
                        (Some(_), None) => false, // parent expires but child doesn't - invalid
                        (Some(pe), Some(de)) => *de <= *pe, // child must expire at or before parent
                    };
                    // not_before: child must become valid at or after parent (None = valid immediately)
                    let not_before_valid = match (&p.not_before, &delegation.not_before) {
                        (None, _) => true, // parent valid immediately, any child not_before is valid
                        (Some(_), None) => false, // parent has restriction but child claims immediate validity
                        (Some(pnbf), Some(dnbf)) => *dnbf >= *pnbf, // child must become valid at or after parent
                    };

                    if !expiry_valid {
                        expiry_failed = true;
                    }
                    if !not_before_valid {
                        not_before_failed = true;
                    }

                    expiry_valid && not_before_valid
                })
                .collect();

            // A policy-session's two sibling proofs are a conjunction.  Do
            // not let one live sibling authorize the child when the other is
            // expired/not-yet-valid, and require every child capability to be
            // contained by every cited root.
            if policy_session && parents.len() != delegation.parents.len() {
                if expiry_failed {
                    return Err(DelegationError::ExpiryExceedsParent.into());
                }
                return Err(DelegationError::NotBeforePrecedesParent.into());
            }

            // If all parents were filtered out due to time constraints, return specific error
            if parents.is_empty() {
                if expiry_failed {
                    return Err(DelegationError::ExpiryExceedsParent.into());
                }
                if not_before_failed {
                    return Err(DelegationError::NotBeforePrecedesParent.into());
                }
            }

            // get delegated abilities from each parent
            let parent_abilities = parents.load_many(abilities::Entity, db).await?;

            if policy_session {
                for c in &dependant_caps {
                    for abilities in &parent_abilities {
                        if !abilities.iter().any(|pc| {
                            c.resource.extends(&pc.resource)
                                && crate::policy_capability::ability_matches(
                                    pc.ability.as_ref().as_ref(),
                                    c.ability.as_ref().as_ref(),
                                )
                        }) {
                            return Err(DelegationError::UnauthorizedCapability(
                                Box::new(c.resource.clone()),
                                c.ability.clone(),
                            )
                            .into());
                        }
                    }
                }
            }

            // W1 caveat-aware containment (audit P0 finding 1): a child cap is
            // supported by a parent cap only when resource+ability extend AND
            // the child's caveats are a subset of the parent's caveats. For
            // SQL constrained-statements caveats we delegate to JCS caveat
            // containment in `sql_caveat::contains`; for other caveat shapes
            // we require structural equality so a child cannot silently
            // replace a parent's caveat.
            for c in &dependant_caps {
                // TC-119: registry-aware ability containment (same primitive as
                // the invocation boundary). A parent ability supports the child
                // when equal OR a registry alias OR an implication of it. Strict
                // widening of the previous `c.ability == pc.ability` — exact
                // matches still match; only registry-declared alias/implication
                // pairs are added.
                let mut candidates = parent_abilities
                    .iter()
                    .flatten()
                    .filter(|pc| {
                        c.resource.extends(&pc.resource)
                            && crate::policy_capability::ability_matches(
                                pc.ability.as_ref().as_ref(),
                                c.ability.as_ref().as_ref(),
                            )
                    })
                    .peekable();

                if candidates.peek().is_none() {
                    return Err(DelegationError::UnauthorizedCapability(
                        Box::new(c.resource.clone()),
                        c.ability.clone(),
                    )
                    .into());
                }

                let mut last_reason: Option<String> = None;
                let mut authorized = false;
                for pc in candidates {
                    match caveats_contain_child(
                        c.ability.as_ref().as_ref(),
                        &pc.caveats,
                        &c.caveats,
                        delegated_sql_caveats,
                    ) {
                        Ok(()) => {
                            authorized = true;
                            break;
                        }
                        Err(reason) => last_reason = Some(reason),
                    }
                }
                if !authorized {
                    let reason = last_reason
                        .unwrap_or_else(|| "child-caveats-not-subset-of-parent".to_string());
                    return Err(DelegationError::CaveatsNotContained(reason).into());
                }
            }
            Ok(())
        }
    }
}

fn is_policy_session(delegation: &TinyCloudDelegation) -> bool {
    let TinyCloudDelegation::Ucan(ucan) = delegation else {
        return false;
    };
    // The profile is a signed selector for conjunctive sibling-root
    // semantics.  A stray fact must never opt a normal UCAN into that path.
    let Some(facts) = ucan.payload().facts.as_ref() else {
        return false;
    };
    if facts.len() != 1 {
        return false;
    }
    let Some(object) = facts[0].as_object() else {
        return false;
    };
    const REQUIRED_FACTS: &[&str] = &[
        "profile",
        "ownerDid",
        "policyId",
        "policyDigestHex",
        "policyCid",
        "policyDelegationCid",
        "enforcementDelegationCid",
        "contentSourceDigestHex",
        "capabilityCeilingHashHex",
        "nativeProjectionHashHex",
        "enforcerDid",
        "nodeAudience",
        "recipientDid",
        "challengeId",
        "claimDigestHex",
        "claimJti",
        "vpDigestHex",
        "credentialEvidenceDigestHex",
        "decisionContextDigestHex",
        "issuanceAuditDigestHex",
        "remainingRedelegationDepth",
    ];
    const V4_AUDIT_FACTS: &[&str] = &[
        "credentialIdAuditDigestHex",
        "presentationJtiAuditDigestHex",
    ];
    let has_v4_audit = V4_AUDIT_FACTS.iter().all(|key| object.contains_key(*key));
    object.len() == REQUIRED_FACTS.len() + usize::from(has_v4_audit) * V4_AUDIT_FACTS.len()
        && object.get("profile").and_then(serde_json::Value::as_str)
            == Some("policy-session-ucan/v1")
        && object.keys().all(|key| {
            REQUIRED_FACTS.contains(&key.as_str()) || V4_AUDIT_FACTS.contains(&key.as_str())
        })
        && REQUIRED_FACTS
            .iter()
            .filter(|key| **key != "remainingRedelegationDepth")
            .all(|key| {
                object
                    .get(*key)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| !value.is_empty())
            })
        && (!has_v4_audit
            || V4_AUDIT_FACTS.iter().all(|key| {
                object
                    .get(*key)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| {
                        value.len() == 64
                            && value
                                .bytes()
                                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                    })
            }))
        && object
            .get("remainingRedelegationDepth")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|depth| depth <= 8)
}

fn is_policy_root(delegation: &TinyCloudDelegation) -> bool {
    let TinyCloudDelegation::Ucan(ucan) = delegation else {
        return false;
    };
    let Some(facts) = ucan.payload().facts.as_ref() else {
        return false;
    };
    if facts.len() != 1 {
        return false;
    }
    let Some(object) = facts[0].as_object() else {
        return false;
    };
    let Some(role) = object.get("role").and_then(serde_json::Value::as_str) else {
        return false;
    };
    if !matches!(role, "policy-authority" | "policy-enforcement") {
        return false;
    }
    let expected = [
        "role",
        "mode",
        "ownerDid",
        "policyId",
        "policyDigestHex",
        "policyCid",
        "contentSourceDigestHex",
        "capabilityCeilingHashHex",
        "nativeProjectionHashHex",
        "nodeAudience",
    ];
    object.len() == expected.len() + usize::from(role == "policy-enforcement")
        && expected.iter().all(|key| {
            object
                .get(*key)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| !value.is_empty())
        })
        && (role != "policy-enforcement"
            || object
                .get("enforcerDid")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| !value.is_empty()))
        && object.get("mode").and_then(serde_json::Value::as_str)
            == Some(if role == "policy-authority" {
                "policy-source"
            } else {
                "conditional-mint"
            })
}

const POLICY_ROOT_FACT_KEY: &str = "xyz.tinycloud.policy/root-profile";
const POLICY_SESSION_FACT_KEY: &str = "xyz.tinycloud.policy/session-fact";

fn signed_policy_fact(
    delegation: &TinyCloudDelegation,
) -> Option<(&'static str, serde_json::Value)> {
    let TinyCloudDelegation::Ucan(ucan) = delegation else {
        return None;
    };
    let facts = ucan.payload().facts.as_ref()?;
    if facts.len() != 1 {
        return None;
    }
    let object = facts[0].as_object()?;
    if object
        .get("role")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|role| role == "policy-authority" || role == "policy-enforcement")
    {
        return Some((POLICY_ROOT_FACT_KEY, facts[0].clone()));
    }
    if is_policy_session(delegation) {
        return Some((POLICY_SESSION_FACT_KEY, facts[0].clone()));
    }
    None
}

enum PolicyDescendantError {
    InvalidFact,
    UnauthorizedDelegator,
    ExpiryExceedsParent,
    NotBeforePrecedesParent,
}

fn validate_policy_descendant(
    child: &util::DelegationInfo,
    parent: &Model,
) -> Result<(), PolicyDescendantError> {
    if child.parents.len() != 1 {
        return Err(PolicyDescendantError::InvalidFact);
    }
    let Some(parent_fact) = parent
        .facts
        .as_ref()
        .and_then(|facts| facts.0.get(POLICY_SESSION_FACT_KEY))
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(());
    };
    if child.delegator != parent.delegatee {
        return Err(PolicyDescendantError::UnauthorizedDelegator);
    }
    if let (Some(parent_expiry), Some(child_expiry)) = (parent.expiry, child.expiry) {
        if child_expiry >= parent_expiry {
            return Err(PolicyDescendantError::ExpiryExceedsParent);
        }
    }
    if let (Some(parent_not_before), Some(child_not_before)) = (parent.not_before, child.not_before)
    {
        if child_not_before <= parent_not_before {
            return Err(PolicyDescendantError::NotBeforePrecedesParent);
        }
    }
    let TinyCloudDelegation::Ucan(ucan) = &child.delegation else {
        return Err(PolicyDescendantError::InvalidFact);
    };
    let Some(facts) = ucan.payload().facts.as_ref() else {
        return Err(PolicyDescendantError::InvalidFact);
    };
    if facts.len() != 1 {
        return Err(PolicyDescendantError::InvalidFact);
    }
    let Some(child_fact) = facts[0].as_object() else {
        return Err(PolicyDescendantError::InvalidFact);
    };
    let parent_depth = parent_fact
        .get("remainingRedelegationDepth")
        .and_then(serde_json::Value::as_u64)
        .ok_or(PolicyDescendantError::InvalidFact)?;
    let child_depth = child_fact
        .get("remainingRedelegationDepth")
        .and_then(serde_json::Value::as_u64)
        .ok_or(PolicyDescendantError::InvalidFact)?;
    if parent_depth == 0 || child_depth + 1 != parent_depth {
        return Err(PolicyDescendantError::InvalidFact);
    }
    let mut expected = parent_fact.clone();
    expected.insert(
        "remainingRedelegationDepth".into(),
        serde_json::Value::from(child_depth),
    );
    if &expected != child_fact {
        return Err(PolicyDescendantError::InvalidFact);
    }
    Ok(())
}

/// W1 (audit P0 finding 1): is `child` a subset of `parent` per JCS caveat
/// containment? Today this distinguishes the SQL constrained-statements
/// caveat (delegating to `sql_caveat::contains` for narrow/identical chain
/// shapes) and otherwise requires structural equality so a child cannot
/// silently drop or replace caveats the parent carried.
fn caveats_contain_child(
    ability: &str,
    parent: &Caveats,
    child: &Caveats,
    delegated_sql_caveats: bool,
) -> Result<(), String> {
    if let Some(contained) = crate::policy_capability::selector_caveats_contain(&parent.0, &child.0)
    {
        return contained
            .then_some(())
            .ok_or_else(|| "selector-caveat-not-contained".to_string());
    }
    // TC-1791: delegated tables / columns / readOnly caveats on SQL
    // abilities. The parent decides which axes the child may not widen.
    if delegated_sql_caveats && ability.starts_with("tinycloud.sql/") {
        use crate::sql::delegated_caveats::{classify, AbilityCaveats, DelegatedCaveat, Reading};
        match (
            classify(parent, Reading::Stored),
            classify(child, Reading::Stored),
        ) {
            (Ok(AbilityCaveats::Form(p)), Ok(AbilityCaveats::Form(c))) => {
                return p.contains(&c).map_err(str::to_string);
            }
            (Ok(AbilityCaveats::Form(p)), Ok(AbilityCaveats::Unrestricted)) => {
                return p
                    .contains(&DelegatedCaveat::default())
                    .map_err(str::to_string);
            }
            (Ok(AbilityCaveats::Form(_)), Ok(AbilityCaveats::Profile)) => {
                return Err("sql-caveats-mixed".to_string());
            }
            // A parent of only empty entries imposes nothing, whatever shape
            // the empty entries take.
            (Ok(AbilityCaveats::Unrestricted), Ok(_)) if !parent.0.is_empty() => {
                return caveats_contain_child(
                    "",
                    &Caveats::default(),
                    child,
                    delegated_sql_caveats,
                );
            }
            _ => {}
        }
    }
    let parent_sql = extract_sql_caveat(parent);
    let child_sql = extract_sql_caveat(child);

    match (parent_sql, child_sql) {
        (Some(p), Some(c)) => sql_caveat::contains(&p, &c).map_err(|e| e.as_str().to_string()),
        (Some(_), None) => Err("containment-caveat-required".to_string()),
        (None, _) => {
            // No SQL caveat on the parent — fall back to structural equality
            // on the raw JSON map so a child cannot inject a brand-new
            // non-SQL caveat that the parent never authorized. If parent
            // has no caveats at all, a child with no caveats is fine; a
            // child that adds caveats is narrowing only when those caveats
            // match an existing parent constraint, so we require equality.
            if parent.0 == child.0 {
                Ok(())
            } else if parent.0.is_empty() {
                // Parent imposed no restrictions; children may introduce
                // narrowing caveats only when those caveats are themselves
                // well-formed for the service. We allow it for now; the
                // service-level enforcement (e.g. SQL constrained-profile)
                // will fail-closed if the new caveat is incoherent.
                Ok(())
            } else {
                Err("child-caveats-not-subset-of-parent".to_string())
            }
        }
    }
}

fn extract_sql_caveat(
    caveats: &Caveats,
) -> Option<crate::policy_capability::SqlConstrainedStatementCaveat> {
    for v in caveats.0.values() {
        if let Ok(c) = sql_caveat::parse(v) {
            return Some(c);
        }
        if let Some(inner) = v.as_object().and_then(|o| o.get("constrained-statements")) {
            if let Ok(c) = sql_caveat::parse(inner) {
                return Some(c);
            }
        }
    }
    None
}

/// True if the persisted parent row is marked terminal via the
/// `xyz.tinycloud.policy/delegationMode` fact. The marker is stored in the
/// `facts` JSON column at save time; absence is treated as attenuable.
fn parent_is_terminal(p: &Model) -> bool {
    let Some(Facts(map)) = &p.facts else {
        return false;
    };
    map.get(DelegationMode::FACT_KEY)
        .and_then(|v| v.as_str())
        .map(|s| s == "terminal")
        .unwrap_or(false)
}

async fn ensure_parent_active<C: ConnectionTrait>(db: &C, parent_id: &Hash) -> Result<(), Error> {
    if revocation::is_revoked(db, parent_id).await? {
        return Err(DelegationError::ParentRevoked(parent_id.to_cid(0x55).to_string()).into());
    }
    let revoked_ancestor = revocation::first_revoked_ancestor(db, parent_id)
        .await
        .map_err(|error| match error {
            revocation::ChainTraversalError::Db(error) => Error::Db(error),
            revocation::ChainTraversalError::LimitExceeded => {
                Error::InvalidDelegation(DelegationError::ChainTraversalLimitExceeded)
            }
        })?;
    if let Some(ancestor_cid) = revoked_ancestor {
        return Err(DelegationError::AncestorRevoked {
            ancestor_cid,
            parent_cid: parent_id.to_cid(0x55).to_string(),
        }
        .into());
    }
    Ok(())
}

fn is_root_authority(cap: &util::Capability, delegator: &str) -> bool {
    if cap
        .resource
        .space()
        .map(|o| did_principal_matches(o.did().as_str(), delegator))
        .unwrap_or(false)
    {
        return true;
    }

    match &cap.resource {
        Resource::Other(uri) => key_id::owned_by(uri.as_str(), delegator),
        Resource::TinyCloud(_) => false,
    }
}

async fn save<C: ConnectionTrait>(
    db: &C,
    delegation: util::DelegationInfo,
    serialization: Vec<u8>,
    encryption: Option<&ColumnEncryption>,
) -> Result<DelegationRegistration, Error> {
    // Hash is always computed on plaintext (before encryption)
    let hash: Hash = crate::hash::hash(&serialization);

    // Encrypt for storage if encryption is configured
    let stored_serialization = crate::encryption::maybe_encrypt(encryption, &serialization);

    // Persist the signed-in `delegationMode` marker. We store ONLY the
    // marker we recognize natively (not the full UCAN facts), keeping the
    // serialization column as the source of truth for the bytes the holder
    // actually signed and the `facts` column as a fast-path lookup index.
    let mut fact_index = BTreeMap::new();
    if matches!(delegation.delegation_mode, DelegationMode::Terminal) {
        fact_index.insert(
            DelegationMode::FACT_KEY.to_string(),
            serde_json::Value::String(DelegationMode::Terminal.as_str().to_string()),
        );
    }
    if let Some((key, value)) = signed_policy_fact(&delegation.delegation) {
        fact_index.insert(key.to_string(), value);
    }
    let facts = (!fact_index.is_empty()).then_some(Facts(fact_index));

    // Actors are FK prerequisites for the delegation row and must be inserted
    // first. They use ON CONFLICT DO NOTHING so concurrent transactions writing
    // the same actors are safe. This is the only write that precedes the
    // idempotency gate below.
    save_actors(&[&delegation.delegator, &delegation.delegate], db).await?;

    // The signed row remains the idempotency gate. Persist its alias in the
    // same transaction; PostgreSQL uses a dependent INSERT CTE to keep the
    // existing registration round-trip budget.
    let canonical = delegation_cid_alias::canonical_hash(&serialization)?;
    let insert = Entity::insert(ActiveModel::from(Model {
        id: hash,
        delegator: delegation.delegator,
        delegatee: delegation.delegate,
        expiry: delegation.expiry,
        issued_at: delegation.issued_at,
        not_before: delegation.not_before,
        facts,
        serialization: stored_serialization,
    }))
    .on_conflict(OnConflict::column(Column::Id).do_nothing().to_owned());
    if db.get_database_backend() == DbBackend::Postgres {
        let claimed = Alias::new("registered_delegation");
        let mut delegation_insert = insert.into_query();
        delegation_insert.returning(Query::returning().column(Column::Id).to_owned());
        let mut alias_insert = Query::insert();
        alias_insert
            .into_table(delegation_cid_alias::Entity)
            .columns([
                delegation_cid_alias::Column::Id,
                delegation_cid_alias::Column::Canonical,
                delegation_cid_alias::Column::Encrypted,
            ])
            .select_from(
                Query::select()
                    .column(Column::Id)
                    .expr(Expr::val(canonical))
                    .expr(Expr::val(encryption.is_some()))
                    .from(claimed.clone())
                    .to_owned(),
            )
            .map_err(|error| DbErr::Custom(error.to_string()))?
            .returning(
                Query::returning()
                    .column(delegation_cid_alias::Column::Id)
                    .to_owned(),
            )
            .with_cte(
                WithClause::new()
                    .cte(
                        CommonTableExpression::new()
                            .table_name(claimed)
                            .query(delegation_insert)
                            .to_owned(),
                    )
                    .to_owned(),
            );
        if db
            .query_one(db.get_database_backend().build(&alias_insert))
            .await?
            .is_none()
        {
            return Ok(DelegationRegistration::Existing(hash));
        }
    } else {
        match insert.exec(db).await {
            Err(DbErr::RecordNotInserted) => return Ok(DelegationRegistration::Existing(hash)),
            result => {
                result?;
            }
        };
        delegation_cid_alias::Entity::insert(delegation_cid_alias::ActiveModel {
            id: Set(hash),
            canonical: Set(canonical),
            encrypted: Set(encryption.is_some()),
        })
        .exec(db)
        .await?;
    }

    // save abilities — persist UCAN caveats with the delegation row. W1
    // contract: caveats MUST NOT be reconstructed from invocation facts;
    // SQL constrained-statement guarantees fail in adversarial cases
    // otherwise (see policy-engine/spec/revocation.md §2.5).
    if !delegation.capabilities.is_empty() {
        abilities::Entity::insert_many(delegation.capabilities.into_iter().map(|ab| {
            abilities::ActiveModel::from(abilities::Model {
                delegation: hash,
                resource: ab.resource,
                ability: ab.ability,
                caveats: ab.caveats,
            })
        }))
        .exec(db)
        .await?;
    }

    // save parent relationships
    if !delegation.parents.is_empty() {
        parent_delegations::Entity::insert_many(delegation.parents.into_iter().map(|p| {
            parent_delegations::ActiveModel::from(parent_delegations::Model {
                child: hash,
                parent: p.into(),
            })
        }))
        .exec(db)
        .await?;
    }

    Ok(DelegationRegistration::New(hash))
}

async fn save_actors<C: ConnectionTrait>(actors: &[&str], db: &C) -> Result<(), DbErr> {
    match actor::Entity::insert_many(actors.iter().map(|a| {
        actor::ActiveModel::from(actor::Model {
            id: ToString::to_string(a),
        })
    }))
    .on_conflict(
        OnConflict::column(actor::Column::Id)
            .do_nothing()
            .to_owned(),
    )
    .exec(db)
    .await
    {
        Err(DbErr::RecordNotInserted) => (),
        r => {
            r?;
        }
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn did_web_refusal_precedes_resolution() {
        use crate::test_support::did_resolution::*;
        use tinycloud_auth::ssi::jwk::{Algorithm, JWK};
        let listener = bound_listener();
        let issuer = format!(
            "did:web:127.0.0.1%3A{}",
            listener.local_addr().unwrap().port()
        );
        let ucan = signed_ucan(&issuer, &JWK::generate_ed25519().unwrap(), Algorithm::EdDSA);
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        let token = ucan.encode().unwrap();
        let event = crate::events::Delegation::from_header_ser::<
            tinycloud_auth::authorization::TinyCloudDelegation,
        >(&token)
        .unwrap();
        let result = super::process(&db, &event, None).await;
        assert!(
            matches!(result, Err(super::Error::InvalidDelegation(super::DelegationError::UnsupportedDidMethod(method))) if method == "web")
        );
        assert_no_connections(&[&listener]).await;
    }
    use super::*;
    use crate::migrations::Migrator;
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database};
    use sea_orm_migration::MigratorTrait;

    async fn database() -> sea_orm::DbConn {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&db, None).await.unwrap();
        db
    }

    async fn insert_delegation(db: &sea_orm::DbConn, id: Hash, delegator: &str, delegatee: &str) {
        for actor_id in [delegator, delegatee] {
            actor::ActiveModel {
                id: Set(actor_id.to_string()),
            }
            .insert(db)
            .await
            .ok();
        }
        ActiveModel {
            id: Set(id),
            delegator: Set(delegator.to_string()),
            delegatee: Set(delegatee.to_string()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(id.as_ref().to_vec()),
        }
        .insert(db)
        .await
        .unwrap();
    }

    // ── DelegationRegistration New/Existing outcome tests ───────────────────

    /// Tests the DB-level ON CONFLICT behaviour that backs DelegationRegistration:
    /// first insert succeeds (→ New), second with same PK gets RecordNotInserted
    /// (→ Existing), both operations produce the same content hash, and the
    /// second insert does not duplicate the ability row.
    #[tokio::test]
    async fn delegation_row_first_insert_new_second_existing() {
        let db = database().await;

        let ser_a = b"delegation-new-existing-bytes-A".to_vec();
        let hash_a = crate::hash::hash(&ser_a);

        for actor in ["did:key:ne-delegator", "did:key:ne-delegatee"] {
            actor::ActiveModel {
                id: Set(actor.to_string()),
            }
            .insert(&db)
            .await
            .ok();
        }

        let model = || ActiveModel {
            id: Set(hash_a),
            delegator: Set("did:key:ne-delegator".to_string()),
            delegatee: Set("did:key:ne-delegatee".to_string()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(ser_a.clone()),
        };

        // First insert → row is new.
        let first = Entity::insert(model())
            .on_conflict(OnConflict::column(Column::Id).do_nothing().to_owned())
            .exec(&db)
            .await;
        let first_reg = match first {
            Ok(_) => DelegationRegistration::New(hash_a),
            Err(DbErr::RecordNotInserted) => DelegationRegistration::Existing(hash_a),
            Err(e) => panic!("unexpected error: {e}"),
        };

        // Ability row for the first insert.
        abilities::Entity::insert(abilities::ActiveModel {
            delegation: Set(hash_a),
            resource: Set("tinycloud:did:key:ne-delegator:files/kv/doc"
                .parse()
                .unwrap()),
            ability: Set("tinycloud.kv/get".to_string().try_into().unwrap()),
            caveats: Set(Default::default()),
        })
        .exec(&db)
        .await
        .unwrap();

        // Second insert → Existing (RecordNotInserted).
        let second = Entity::insert(model())
            .on_conflict(OnConflict::column(Column::Id).do_nothing().to_owned())
            .exec(&db)
            .await;
        let second_reg = match second {
            Ok(_) => DelegationRegistration::New(hash_a),
            Err(DbErr::RecordNotInserted) => DelegationRegistration::Existing(hash_a),
            Err(e) => panic!("unexpected error: {e}"),
        };

        assert!(first_reg.is_new(), "first insert must be New");
        assert!(
            matches!(second_reg, DelegationRegistration::Existing(_)),
            "second insert must be Existing"
        );
        assert_eq!(
            first_reg.hash(),
            second_reg.hash(),
            "both registrations must report the same hash"
        );

        // Exactly one ability row — second save must not duplicate.
        let count = abilities::Entity::find()
            .filter(abilities::Column::Delegation.eq(hash_a))
            .count(&db)
            .await
            .unwrap();
        assert_eq!(count, 1, "Existing must not insert duplicate ability rows");
    }

    /// Two delegations with distinct serialization bytes produce distinct hashes
    /// and neither satisfies the other's exact-hash idempotency predicate.
    #[tokio::test]
    async fn distinct_delegations_yield_distinct_hashes() {
        let db = database().await;

        let ser_a = b"delegation-distinct-alpha".to_vec();
        let ser_b = b"delegation-distinct-beta".to_vec();
        let hash_a = crate::hash::hash(&ser_a);
        let hash_b = crate::hash::hash(&ser_b);

        assert_ne!(
            hash_a, hash_b,
            "distinct serialization bytes must produce distinct hashes"
        );

        for actor in ["did:key:dist-a", "did:key:dist-b"] {
            actor::ActiveModel {
                id: Set(actor.to_string()),
            }
            .insert(&db)
            .await
            .ok();
        }

        for (hash, ser) in [(hash_a, ser_a), (hash_b, ser_b)] {
            Entity::insert(ActiveModel {
                id: Set(hash),
                delegator: Set("did:key:dist-a".to_string()),
                delegatee: Set("did:key:dist-b".to_string()),
                expiry: Set(None),
                issued_at: Set(None),
                not_before: Set(None),
                facts: Set(None),
                serialization: Set(ser),
            })
            .on_conflict(OnConflict::column(Column::Id).do_nothing().to_owned())
            .exec(&db)
            .await
            .unwrap();
        }

        // hash_a row exists but hash_b lookup returns it — must not.
        let row_for_a = Entity::find_by_id(hash_a).one(&db).await.unwrap();
        let row_for_b = Entity::find_by_id(hash_b).one(&db).await.unwrap();
        assert!(row_for_a.is_some());
        assert!(row_for_b.is_some());
        // Neither hash satisfies the other delegation's exact-byte predicate.
        assert_ne!(
            row_for_a.unwrap().id,
            row_for_b.unwrap().id,
            "distinct delegations must not share a primary key"
        );
    }

    #[tokio::test]
    async fn new_child_from_revoked_parent_is_rejected() {
        let db = database().await;
        let parent_id = crate::hash::hash(b"revoked-parent");
        insert_delegation(&db, parent_id, "did:key:owner", "did:key:holder").await;
        revocation::ActiveModel {
            id: Set(crate::hash::hash(b"parent-revocation")),
            revoker: Set("did:key:owner".to_string()),
            revoked: Set(parent_id),
            serialization: Set(b"parent-revocation".to_vec()),
            revoked_at: Set(Some(OffsetDateTime::now_utc())),
        }
        .insert(&db)
        .await
        .unwrap();

        let error = ensure_parent_active(&db, &parent_id)
            .await
            .expect_err("a revoked parent must not authorize a new child");
        assert!(matches!(
            error,
            Error::InvalidDelegation(DelegationError::ParentRevoked(_))
        ));
    }

    /// TC-1791: an SQL grant with a caveat outside the
    /// constrained-statements profile is refused.
    #[tokio::test]
    async fn sql_delegation_with_unsupported_caveat_key_is_refused() {
        let db = database().await;
        let info = root_delegation_info(
            "tinycloud.sql/read",
            "files/sql/main",
            serde_json::json!({"tables": ["a"]}),
        );
        let result = validate(&db, &info).await;
        assert!(
            matches!(
                result,
                Err(Error::InvalidDelegation(
                    DelegationError::UnsupportedCaveat(_)
                ))
            ),
            "expected UnsupportedCaveat, got {result:?}"
        );
    }

    fn assert_unsupported_caveat(result: Result<(), Error>) {
        assert!(
            matches!(
                result,
                Err(Error::InvalidDelegation(
                    DelegationError::UnsupportedCaveat(_)
                ))
            ),
            "expected UnsupportedCaveat, got {result:?}"
        );
    }

    /// TC-1791: a constrained-statements entry mixed with other keys is refused.
    #[tokio::test]
    async fn sql_delegation_mixing_profile_with_other_keys_is_refused() {
        let db = database().await;
        let info = root_delegation_info(
            "tinycloud.sql/read",
            "files/sql/main",
            serde_json::json!({
                "constrained-statements": constrained_profile(),
                "tables": ["a"]
            }),
        );
        assert_unsupported_caveat(validate(&db, &info).await);
    }

    /// TC-1791: the SQL caveat rule applies to the wildcard SQL ability.
    #[tokio::test]
    async fn sql_wildcard_delegation_with_unsupported_caveat_is_refused() {
        let db = database().await;
        let info = root_delegation_info(
            "tinycloud.sql/*",
            "files/sql/main",
            serde_json::json!({"tables": ["a"]}),
        );
        assert_unsupported_caveat(validate(&db, &info).await);
    }

    /// TC-1791: a caveat array of an empty object and a profile is refused,
    /// because the empty object at index 0 is not a profile.
    #[tokio::test]
    async fn sql_delegation_with_empty_object_beside_profile_is_refused() {
        let db = database().await;
        let mut info = root_delegation_info(
            "tinycloud.sql/read",
            "files/sql/main",
            serde_json::json!({}),
        );
        info.capabilities[0].caveats = crate::types::Caveats(std::collections::BTreeMap::from([
            ("0".to_string(), serde_json::json!({})),
            ("1".to_string(), constrained_profile()),
        ]));
        assert_unsupported_caveat(validate(&db, &info).await);
    }

    /// TC-1791: the SQL caveat rule applies to the admin SQL ability.
    #[tokio::test]
    async fn sql_admin_delegation_with_unsupported_caveat_is_refused() {
        let db = database().await;
        let info = root_delegation_info(
            "tinycloud.sql/admin",
            "files/sql/main",
            serde_json::json!({"tables": ["a"]}),
        );
        assert_unsupported_caveat(validate(&db, &info).await);
    }

    /// TC-1791: a chained (non-owner) SQL delegation with an unsupported caveat
    /// is refused before the parent check runs.
    #[tokio::test]
    async fn chained_sql_delegation_with_unsupported_caveat_is_refused() {
        let db = database().await;
        let mut info = root_delegation_info(
            "tinycloud.sql/read",
            "files/sql/main",
            serde_json::json!({"tables": ["a"]}),
        );
        info.delegator = "did:key:z6MkchainedDelegatorNotOwner".to_string();
        assert_unsupported_caveat(validate(&db, &info).await);
    }

    /// TC-1791: a chained SQL delegation with a supported profile reaches the
    /// parent check and is rejected there for missing parents.
    #[tokio::test]
    async fn chained_sql_delegation_with_constrained_profile_reaches_parent_check() {
        let db = database().await;
        let mut info = root_delegation_info(
            "tinycloud.sql/read",
            "files/sql/main",
            constrained_profile(),
        );
        info.delegator = "did:key:z6MkchainedDelegatorNotOwner".to_string();
        assert!(matches!(
            validate(&db, &info).await,
            Err(Error::InvalidDelegation(DelegationError::MissingParents))
        ));
    }

    /// TC-1791: DuckDB accepts empty caveats only, so a constrained-statements
    /// profile is refused.
    #[tokio::test]
    async fn duckdb_delegation_with_constrained_profile_is_refused() {
        let db = database().await;
        let info = root_delegation_info(
            "tinycloud.duckdb/read",
            "files/duckdb/main",
            constrained_profile(),
        );
        assert_unsupported_caveat(validate(&db, &info).await);
    }

    /// TC-1791: a DuckDB grant without caveats is accepted.
    #[tokio::test]
    async fn duckdb_delegation_without_caveats_is_accepted() {
        let db = database().await;
        let mut info = root_delegation_info(
            "tinycloud.duckdb/write",
            "files/duckdb/main",
            constrained_profile(),
        );
        info.capabilities[0].caveats = crate::types::Caveats(std::collections::BTreeMap::new());
        validate(&db, &info)
            .await
            .expect("a DuckDB grant without caveats is accepted");
    }

    /// TC-1791: a direct constrained-statements profile is a supported SQL caveat.
    #[tokio::test]
    async fn sql_delegation_with_constrained_profile_is_accepted() {
        let db = database().await;
        let info = root_delegation_info(
            "tinycloud.sql/read",
            "files/sql/main",
            constrained_profile(),
        );
        validate(&db, &info)
            .await
            .expect("a constrained-statements profile is accepted");
    }

    /// TC-1791: a constrained-statements profile nested under its own key is accepted.
    #[tokio::test]
    async fn sql_delegation_with_nested_constrained_profile_is_accepted() {
        let db = database().await;
        let info = root_delegation_info(
            "tinycloud.sql/read",
            "files/sql/main",
            serde_json::json!({"constrained-statements": constrained_profile()}),
        );
        validate(&db, &info)
            .await
            .expect("a nested constrained-statements profile is accepted");
    }

    /// TC-1791: an SQL grant without caveats is not affected by the profile rule.
    #[tokio::test]
    async fn sql_delegation_without_caveats_is_accepted() {
        let db = database().await;
        let mut info = root_delegation_info(
            "tinycloud.sql/read",
            "files/sql/main",
            constrained_profile(),
        );
        info.capabilities[0].caveats = crate::types::Caveats(std::collections::BTreeMap::new());
        validate(&db, &info)
            .await
            .expect("an SQL grant without caveats is accepted");
    }

    /// TC-1791: DuckDB gets the same refusal as SQL for non-profile caveats.
    #[tokio::test]
    async fn duckdb_delegation_with_unsupported_caveat_key_is_refused() {
        let db = database().await;
        let info = root_delegation_info(
            "tinycloud.duckdb/write",
            "files/duckdb/main",
            serde_json::json!({"readOnly": true}),
        );
        let result = validate(&db, &info).await;
        assert!(
            matches!(
                result,
                Err(Error::InvalidDelegation(
                    DelegationError::UnsupportedCaveat(_)
                ))
            ),
            "expected UnsupportedCaveat, got {result:?}"
        );
    }

    /// TC-1791: the profile rule is scoped to SQL and DuckDB abilities.
    #[tokio::test]
    async fn non_sql_delegation_caveats_are_not_checked_by_sql_rule() {
        let db = database().await;
        let info = root_delegation_info(
            "tinycloud.kv/read",
            "files/kv/main",
            serde_json::json!({"tables": ["a"]}),
        );
        validate(&db, &info)
            .await
            .expect("only SQL and DuckDB caveats are checked by this rule");
    }

    fn constrained_profile() -> serde_json::Value {
        serde_json::json!({
            "mode": "constrained-statements",
            "readOnly": true,
            "statements": [{"name": "recent", "sql": "SELECT 1"}]
        })
    }

    fn root_delegation_info(
        ability: &str,
        path: &str,
        nb: serde_json::Value,
    ) -> util::DelegationInfo {
        use crate::test_support::did_resolution::signed_ucan;
        use tinycloud_auth::ssi::jwk::{Algorithm, JWK};
        let delegator = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let ucan = signed_ucan(
            delegator,
            &JWK::generate_ed25519().unwrap(),
            Algorithm::EdDSA,
        );
        util::DelegationInfo {
            capabilities: vec![util::Capability {
                resource: format!("tinycloud:{}:{path}", delegator.trim_start_matches("did:"))
                    .parse()
                    .unwrap(),
                ability: ability.to_string().try_into().unwrap(),
                caveats: crate::types::Caveats(std::collections::BTreeMap::from([(
                    "0".to_string(),
                    nb,
                )])),
            }],
            delegator: delegator.to_string(),
            delegate: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".to_string(),
            parents: vec![],
            delegation: tinycloud_auth::authorization::TinyCloudDelegation::Ucan(Box::new(ucan)),
            expiry: None,
            not_before: None,
            issued_at: None,
            delegation_mode: util::DelegationMode::Attenuable,
        }
    }

    const KEY_OWNER: &str = "did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
    const KEY_RESOURCE: &str = "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/apps/tinychat";
    const OTHER_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    fn key_delegation_info(delegator: &str, ability: &str) -> util::DelegationInfo {
        use crate::test_support::did_resolution::signed_ucan;
        use tinycloud_auth::ssi::jwk::{Algorithm, JWK};
        let ucan = signed_ucan(
            OTHER_DID,
            &JWK::generate_ed25519().unwrap(),
            Algorithm::EdDSA,
        );
        util::DelegationInfo {
            capabilities: vec![util::Capability {
                resource: KEY_RESOURCE.parse().unwrap(),
                ability: ability.to_string().try_into().unwrap(),
                caveats: crate::types::Caveats::default(),
            }],
            delegator: delegator.to_string(),
            delegate: OTHER_DID.to_string(),
            parents: vec![],
            delegation: tinycloud_auth::authorization::TinyCloudDelegation::Ucan(Box::new(ucan)),
            expiry: None,
            not_before: None,
            issued_at: None,
            delegation_mode: util::DelegationMode::Attenuable,
        }
    }

    /// The key owner is root authority for keys under its own namespace.
    #[tokio::test]
    async fn owner_issued_key_grant_is_admitted_without_parents() {
        let db = database().await;
        let info = key_delegation_info(KEY_OWNER, "tinycloud.encryption/key.create");
        validate(&db, &info)
            .await
            .expect("owner is root authority for own keys");
    }

    /// A delegator that does not own the key must cite parents.
    #[tokio::test]
    async fn non_owner_key_grant_without_parents_is_refused() {
        let db = database().await;
        let info = key_delegation_info(OTHER_DID, "tinycloud.encryption/key.create");
        assert!(matches!(
            validate(&db, &info).await,
            Err(Error::InvalidDelegation(DelegationError::MissingParents))
        ));
    }

    /// Without named keys, a grant on a key or a key prefix is refused for
    /// the key's owner and for anyone else, before any parent is looked up;
    /// a grant on the bare network is not affected.
    #[tokio::test]
    async fn named_key_grants_are_refused_when_named_keys_are_off() {
        let db = database().await;
        let key = KEY_RESOURCE.to_string();
        let prefix = format!("urn:tinycloud:encryption:{KEY_OWNER}:default/apps/");
        let network = format!("urn:tinycloud:encryption:{KEY_OWNER}:default");
        for delegator in [KEY_OWNER, OTHER_DID] {
            for resource in [&key, &prefix] {
                let info = key_grant_info(delegator, resource, KEY_DECRYPT, &[]);
                let refused = validate_with(&db, &info, false, false).await;
                assert!(
                    matches!(
                        refused,
                        Err(Error::InvalidDelegation(
                            DelegationError::NamedKeysUnavailable
                        ))
                    ),
                    "{delegator} on {resource}: {refused:?}"
                );
            }
        }
        assert_eq!(
            DelegationError::NamedKeysUnavailable.to_string(),
            "named_keys_unavailable: named keys are not enabled on this node"
        );
        let info = key_grant_info(KEY_OWNER, &network, KEY_DECRYPT, &[]);
        validate_with(&db, &info, false, false)
            .await
            .expect("the owner's bare network grant is not a named-key grant");
        let info = key_grant_info(KEY_OWNER, &key, KEY_DECRYPT, &[]);
        validate_with(&db, &info, false, true)
            .await
            .expect("the same grant is admitted with named keys on");
    }

    /// key.delete is refused even when the owner issues it.
    #[tokio::test]
    async fn owner_issued_key_delete_is_refused() {
        let db = database().await;
        let info = key_delegation_info(KEY_OWNER, "tinycloud.encryption/key.delete");
        assert!(matches!(
            validate(&db, &info).await,
            Err(Error::InvalidDelegation(
                DelegationError::KeyDeleteNotDelegable
            ))
        ));
    }

    /// key.delete refusal runs before the parent check, so a non-owner
    /// delete without parents reports the delete refusal.
    #[tokio::test]
    async fn non_owner_key_delete_is_refused_before_parent_check() {
        let db = database().await;
        let info = key_delegation_info(OTHER_DID, "tinycloud.encryption/key.delete");
        assert!(matches!(
            validate(&db, &info).await,
            Err(Error::InvalidDelegation(
                DelegationError::KeyDeleteNotDelegable
            ))
        ));
    }

    /// key.delete is refused for the owner even when a parent is cited. The
    /// refusal runs before the root-authority filter and the parent branches.
    #[tokio::test]
    async fn owner_issued_key_delete_with_parent_is_refused() {
        let db = database().await;
        let parent = crate::hash::hash(b"owner-delete-with-parent");
        let prefix = format!("urn:tinycloud:encryption:{KEY_OWNER}:default/apps/");
        insert_parent_grant(&db, parent, KEY_OWNER, OTHER_DID, &prefix, KEY_DECRYPT).await;
        let info = key_grant_info(
            KEY_OWNER,
            KEY_RESOURCE,
            "tinycloud.encryption/key.delete",
            &[parent],
        );
        assert!(matches!(
            validate(&db, &info).await,
            Err(Error::InvalidDelegation(
                DelegationError::KeyDeleteNotDelegable
            ))
        ));
    }

    fn key_grant_info(
        delegator: &str,
        resource: &str,
        ability: &str,
        parents: &[Hash],
    ) -> util::DelegationInfo {
        use crate::test_support::did_resolution::signed_ucan;
        use tinycloud_auth::ssi::jwk::{Algorithm, JWK};
        let ucan = signed_ucan(
            OTHER_DID,
            &JWK::generate_ed25519().unwrap(),
            Algorithm::EdDSA,
        );
        util::DelegationInfo {
            capabilities: vec![util::Capability {
                resource: resource.parse().unwrap(),
                ability: ability.to_string().try_into().unwrap(),
                caveats: crate::types::Caveats::default(),
            }],
            delegator: delegator.to_string(),
            delegate: OTHER_DID.to_string(),
            parents: parents.iter().map(|parent| parent.to_cid(0x55)).collect(),
            delegation: tinycloud_auth::authorization::TinyCloudDelegation::Ucan(Box::new(ucan)),
            expiry: None,
            not_before: None,
            issued_at: None,
            delegation_mode: util::DelegationMode::Attenuable,
        }
    }

    /// Inserts a grant (delegation row plus ability row) that a child can cite.
    async fn insert_parent_grant(
        db: &sea_orm::DbConn,
        id: Hash,
        delegator: &str,
        delegatee: &str,
        resource: &str,
        ability: &str,
    ) {
        insert_delegation(db, id, delegator, delegatee).await;
        abilities::Entity::insert(abilities::ActiveModel {
            delegation: Set(id),
            resource: Set(resource.parse().unwrap()),
            ability: Set(ability.to_string().try_into().unwrap()),
            caveats: Set(Default::default()),
        })
        .exec(db)
        .await
        .unwrap();
    }

    const KEY_DECRYPT: &str = "tinycloud.encryption/decrypt";

    /// A prefix grant cited as a parent covers a key below it.
    #[tokio::test]
    async fn key_prefix_grant_covers_key_below_it_through_parent() {
        let db = database().await;
        let parent = crate::hash::hash(b"prefix-grant-covers-key");
        let prefix = format!("urn:tinycloud:encryption:{KEY_OWNER}:default/apps/foo/");
        insert_parent_grant(&db, parent, KEY_OWNER, OTHER_DID, &prefix, KEY_DECRYPT).await;
        let key = format!("urn:tinycloud:encryption:{KEY_OWNER}:default/apps/foo/x");
        let info = key_grant_info(OTHER_DID, &key, KEY_DECRYPT, &[parent]);
        validate(&db, &info)
            .await
            .expect("parent prefix covers key below it");
    }

    /// A child prefix wider than the parent's prefix is not covered.
    #[tokio::test]
    async fn broader_child_prefix_is_not_covered_by_parent() {
        let db = database().await;
        let parent = crate::hash::hash(b"prefix-grant-narrow");
        let prefix = format!("urn:tinycloud:encryption:{KEY_OWNER}:default/apps/foo/");
        insert_parent_grant(&db, parent, KEY_OWNER, OTHER_DID, &prefix, KEY_DECRYPT).await;
        let child = format!("urn:tinycloud:encryption:{KEY_OWNER}:default/apps/");
        let info = key_grant_info(OTHER_DID, &child, KEY_DECRYPT, &[parent]);
        assert!(matches!(
            validate(&db, &info).await,
            Err(Error::InvalidDelegation(
                DelegationError::UnauthorizedCapability(_, _)
            ))
        ));
    }

    /// A parent issued in another owner's namespace does not cover this owner's key.
    #[tokio::test]
    async fn parent_for_other_owner_does_not_cover_key() {
        const OTHER_OWNER: &str = "did:pkh:eip155:1:0x0000000000000000000000000000000000000001";
        let db = database().await;
        let parent = crate::hash::hash(b"prefix-grant-other-owner");
        let prefix = format!("urn:tinycloud:encryption:{OTHER_OWNER}:default/apps/foo/");
        insert_parent_grant(&db, parent, OTHER_OWNER, OTHER_DID, &prefix, KEY_DECRYPT).await;
        let key = format!("urn:tinycloud:encryption:{KEY_OWNER}:default/apps/foo/x");
        let info = key_grant_info(OTHER_DID, &key, KEY_DECRYPT, &[parent]);
        assert!(matches!(
            validate(&db, &info).await,
            Err(Error::InvalidDelegation(
                DelegationError::UnauthorizedCapability(_, _)
            ))
        ));
    }

    /// key.delete is refused in a chain even when a parent grants the key's prefix.
    #[tokio::test]
    async fn chained_key_delete_is_refused_with_parent_cited() {
        let db = database().await;
        let parent = crate::hash::hash(b"prefix-grant-for-chained-delete");
        let prefix = format!("urn:tinycloud:encryption:{KEY_OWNER}:default/apps/");
        insert_parent_grant(&db, parent, KEY_OWNER, OTHER_DID, &prefix, KEY_DECRYPT).await;
        let info = key_grant_info(
            OTHER_DID,
            KEY_RESOURCE,
            "tinycloud.encryption/key.delete",
            &[parent],
        );
        assert!(matches!(
            validate(&db, &info).await,
            Err(Error::InvalidDelegation(
                DelegationError::KeyDeleteNotDelegable
            ))
        ));
    }

    /// Malformed key identifiers are not root authority, even for the owner,
    /// and a valid parent prefix does not cover them.
    #[tokio::test]
    async fn malformed_key_identifiers_are_refused_in_delegations() {
        let db = database().await;
        let prefix = format!("urn:tinycloud:encryption:{KEY_OWNER}:default/apps/");
        let mut skipped = 0;
        for (index, resource) in key_id::MALFORMED_KEY_IDS.iter().enumerate() {
            // Ids that fail URI parsing cannot be built into a capability, so there is nothing to admit or refuse.
            if resource.parse::<crate::types::Resource>().is_err() {
                skipped += 1;
                continue;
            }
            let owner_info =
                key_grant_info(KEY_OWNER, resource, "tinycloud.encryption/key.create", &[]);
            assert!(
                matches!(
                    validate(&db, &owner_info).await,
                    Err(Error::InvalidDelegation(DelegationError::MissingParents))
                ),
                "owner-issued malformed key {} accepted: {resource}",
                index + 7
            );
            let parent = crate::hash::hash(resource.as_bytes());
            insert_parent_grant(&db, parent, KEY_OWNER, OTHER_DID, &prefix, KEY_DECRYPT).await;
            let info = key_grant_info(OTHER_DID, resource, KEY_DECRYPT, &[parent]);
            assert!(
                matches!(
                    validate(&db, &info).await,
                    Err(Error::InvalidDelegation(
                        DelegationError::UnauthorizedCapability(_, _)
                    ))
                ),
                "parent covered malformed key {}: {resource}",
                index + 7
            );
        }
        assert_eq!(
            skipped, 2,
            "URI-invalid key identifiers in MALFORMED_KEY_IDS"
        );
    }

    /// Inserts a terminal grant (`disableSubDelegation: true`) that a child may cite.
    async fn insert_terminal_parent_grant(
        db: &sea_orm::DbConn,
        id: Hash,
        delegator: &str,
        delegatee: &str,
        resource: &str,
        ability: &str,
    ) {
        for actor_id in [delegator, delegatee] {
            actor::ActiveModel {
                id: Set(actor_id.to_string()),
            }
            .insert(db)
            .await
            .ok();
        }
        ActiveModel {
            id: Set(id),
            delegator: Set(delegator.to_string()),
            delegatee: Set(delegatee.to_string()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(Some(Facts(BTreeMap::from([(
                DelegationMode::FACT_KEY.to_string(),
                serde_json::json!("terminal"),
            )])))),
            serialization: Set(id.as_ref().to_vec()),
        }
        .insert(db)
        .await
        .unwrap();
        abilities::Entity::insert(abilities::ActiveModel {
            delegation: Set(id),
            resource: Set(resource.parse().unwrap()),
            ability: Set(ability.to_string().try_into().unwrap()),
            caveats: Set(Default::default()),
        })
        .exec(db)
        .await
        .unwrap();
    }

    /// A terminal grant cannot be cited as a parent for a redelegation, even when it covers the child's resource.
    #[tokio::test]
    async fn terminal_parent_grant_cannot_be_redelegated() {
        let db = database().await;
        let parent = crate::hash::hash(b"terminal-parent-grant");
        let prefix = format!("urn:tinycloud:encryption:{KEY_OWNER}:default/apps/foo/");
        insert_terminal_parent_grant(&db, parent, KEY_OWNER, OTHER_DID, &prefix, KEY_DECRYPT).await;
        let key = format!("urn:tinycloud:encryption:{KEY_OWNER}:default/apps/foo/x");
        let info = key_grant_info(OTHER_DID, &key, KEY_DECRYPT, &[parent]);
        assert!(
            matches!(
                validate(&db, &info).await,
                Err(Error::InvalidDelegation(
                    DelegationError::TerminalParentCannotRedelegate
                ))
            ),
            "terminal parent accepted for redelegation"
        );
    }

    fn wire(list: serde_json::Value) -> Caveats {
        let entries = list.as_array().expect("a list");
        if entries.len() == 1 && entries[0] == serde_json::json!({}) {
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

    /// TC-1791: the per-hop containment of the delegated form goes through the
    /// same `caveats_contain_child` as every other caveat (S1 to S8).
    #[test]
    fn delegated_form_hops_are_contained_per_axis() {
        use serde_json::json;
        const SQL: &str = "tinycloud.sql/read";
        let ok = |parent: serde_json::Value, child: serde_json::Value| {
            caveats_contain_child(SQL, &wire(parent), &wire(child), true)
        };
        assert!(ok(
            json!([{"tables": ["Notes", "t2"]}]),
            json!([{"tables": ["Notes"]}])
        )
        .is_ok()); // S1
        assert!(ok(
            json!([{"tables": ["Notes"]}]),
            json!([{"tables": ["Notes", "plain"]}])
        )
        .is_err()); // S2
        assert!(ok(json!([{}]), json!([{"tables": ["Notes"]}])).is_ok()); // S3
        assert!(ok(json!([{"readOnly": true}]), json!([{"readOnly": false}])).is_err()); // S4
        assert!(ok(json!([{"readOnly": true}]), json!([{}])).is_err()); // S4
        assert!(ok(json!([{}]), json!([{"readOnly": true}])).is_ok()); // S4
        assert!(ok(
            json!([{"columns": ["id"]}]),
            json!([{"columns": ["id", "body"]}])
        )
        .is_err()); // S5
        assert!(ok(json!([{"columns": ["id"]}]), json!([{"columns": ["id"]}])).is_ok()); // S5
        assert!(ok(
            json!([{"tables": ["notes"]}]),
            json!([{"tables": ["NOTES"]}])
        )
        .is_ok()); // S6
        assert!(ok(json!([{}]), json!([{}])).is_ok()); // S7
        assert!(ok(json!([{"tables": ["a"]}]), json!([{}])).is_err()); // S7
        assert!(ok(json!([{"tables": ["Notes"]}]), json!([{"readOnly": true}])).is_err()); // S8
                                                                                           // A parent of only empty entries imposes nothing, in any shape.
        assert!(ok(json!([{}, {}]), json!([{"tables": ["a"]}])).is_ok());
        assert!(ok(json!([{}, {}]), json!([{}])).is_ok());
        assert!(ok(json!([{}, {}]), json!([{}, {}])).is_ok());
        // A profile and the delegated form do not mix across a hop.
        let profile = json!({"mode": "constrained-statements", "readOnly": true,
                             "statements": [{"name": "n", "sql": "SELECT 1"}]});
        assert!(ok(json!([{"tables": ["a"]}]), json!([profile.clone()])).is_err());
        assert!(ok(json!([profile]), json!([{"tables": ["a"]}])).is_err());
        // Other services: equal caveats, or an empty parent.
        let kv = |parent: serde_json::Value, child: serde_json::Value| {
            caveats_contain_child("tinycloud.kv/get", &wire(parent), &wire(child), true)
        };
        assert!(kv(json!([{}, {}]), json!([{"tables": ["a"]}])).is_err());
        assert!(kv(json!([{}]), json!([{"tables": ["a"]}])).is_ok());

        // Setting off: SQL caveats are contained as every other caveat is
        // (equal caveats, or an empty parent).
        let off = |parent: serde_json::Value, child: serde_json::Value| {
            caveats_contain_child(SQL, &wire(parent), &wire(child), false)
        };
        assert!(off(json!([{}, {}]), json!([{"tables": ["a"]}])).is_err());
        assert!(off(json!([{}, {}]), json!([{}])).is_err());
        assert!(off(json!([{}]), json!([{"tables": ["a"]}])).is_ok());
        assert!(off(json!([{"tables": ["a"]}]), json!([{"tables": ["a"]}])).is_ok());
        assert!(off(json!([{"tables": ["a"]}]), json!([{"tables": ["A"]}])).is_err());
        assert!(off(json!([{"tables": ["a"]}]), json!([{}])).is_err());
    }
}
