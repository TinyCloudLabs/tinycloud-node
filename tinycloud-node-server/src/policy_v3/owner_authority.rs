//! TC-1423: record which delegations a Policy/v3 owner held as authority.
//!
//! A policy root is parentless and signed by the policy owner, so the
//! ordinary graph cannot tell which owner delegation the root's authority
//! came from. Registration therefore selects, per root capability, the owner
//! delegation that grants it and records that delegation's whole ancestor
//! closure. Policies registered before the binding tables existed are
//! classified on first use (claim-first, served from memory when the write
//! fails) or by the opt-in sweep.
//!
//! Selection per capability:
//! - root authority (the owner owns the space or encryption network) needs
//!   no delegation;
//! - step 1 looks only at delegations to the owner issued by the owner of
//!   that capability's space or network, the only principal that can issue
//!   them, so delegations from strangers cannot push them out of the window;
//! - step 2 falls back to the general window of delegations to the owner;
//! - a candidate whose closure contains a delegation issued by the policy
//!   owner itself is skipped: authority that loops back through the owner key
//!   adds nothing and would let a downstream holder steer the record;
//! - among satisfying candidates the first, newest-first, whose closure
//!   outlives the policy root wins, else the newest.

use super::*;
use crate::config::OwnerAuthorityExpiry;
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use tinycloud_core::{
    encryption_network::NetworkId,
    hash::Hash,
    models::{
        abilities,
        invocation::{Error as InvocationModelError, InvocationError},
        policy_v3_owner_authority, policy_v3_owner_binding,
    },
    policy_owner_authority::{self as authority_graph, ChainTraversalError, ClosureNode},
    sea_orm::{
        sea_query::{Func, Query},
        DbErr,
    },
    types::{Ability, Resource},
    util::Capability,
};

/// Bump when classification rules change: `unknown` rows written by an
/// older version are classified again on their next use.
pub(super) const CLASSIFIER_VERSION: i32 = 3;
/// Ability that lets an owner hold a policy root through the register grant.
const REGISTER_ABILITY: &str = "tinycloud.policy/register";
/// Owner-first rows examined per capability (step 1).
const OWNER_FIRST_ROWS: u64 = 64;
/// Listing page size.
const LISTING_PAGE: u64 = 100;
/// How long a background classification waits for the SQLite writer.
const LAZY_WRITE_LOCK_WAIT: std::time::Duration = std::time::Duration::from_millis(250);
/// A classification computed for a request that isn't final (its write
/// failed, or it ended `starved`) is reused for this long before it is
/// recomputed.
const RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60);
/// Bound on the process-local sets below; a full set is cleared.
const MAX_TRACKED_POLICIES: usize = 65_536;
/// Background classification writes running at once, process-wide.
const MAX_BACKGROUND_CLASSIFICATIONS: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingState {
    /// At least one delegation recorded; the root expires no later than it.
    Bound,
    /// At least one delegation recorded; the root outlives it.
    BoundUncapped,
    /// Every capability is held as root authority.
    RootAuthority,
    /// No authority found.
    Unknown,
}

impl BindingState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::BoundUncapped => "bound-uncapped",
            Self::RootAuthority => "root-authority",
            Self::Unknown => "unknown",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "bound" => Self::Bound,
            "bound-uncapped" => Self::BoundUncapped,
            "root-authority" => Self::RootAuthority,
            "unknown" => Self::Unknown,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownReason {
    /// A candidate satisfied the capability except that it, or an ancestor,
    /// is revoked.
    Revoked,
    /// No candidate satisfied the capability.
    Missing,
    /// No candidate satisfied the capability within the examined windows,
    /// and more delegations to the owner exist than were examined.
    Starved,
    /// Registered after the legacy cutover without a classification, and
    /// its root breaks the registration-time lifetime cap.
    LifetimeExceeded,
    /// Registered after the legacy cutover without a classification, and
    /// under `enforce` its root outlives the recorded authority.
    OutlivesAuthority,
}

impl UnknownReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Revoked => "revoked",
            Self::Missing => "missing",
            Self::Starved => "starved",
            Self::LifetimeExceeded => "lifetime-exceeded",
            Self::OutlivesAuthority => "outlives-authority",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "revoked" => Self::Revoked,
            "missing" => Self::Missing,
            "starved" => Self::Starved,
            "lifetime-exceeded" => Self::LifetimeExceeded,
            "outlives-authority" => Self::OutlivesAuthority,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisteredMode {
    /// Classified at registration, without refusing roots that outlive
    /// their authority.
    Record,
    /// Classified at registration, refusing roots that outlive their
    /// authority.
    Enforce,
    /// Classified after registration, for a policy registered before the
    /// legacy cutover.
    Backfill,
}

impl RegisteredMode {
    pub(super) fn current(expiry: OwnerAuthorityExpiry) -> Self {
        match expiry {
            OwnerAuthorityExpiry::Record => Self::Record,
            OwnerAuthorityExpiry::Enforce => Self::Enforce,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Record => "record",
            Self::Enforce => "enforce",
            Self::Backfill => "backfill",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "record" => Self::Record,
            "enforce" => Self::Enforce,
            "backfill" => Self::Backfill,
            _ => return None,
        })
    }
}

/// A classification as a policy use checks it.
#[derive(Clone, Debug)]
pub(super) struct Binding {
    state: BindingState,
    reason: Option<UnknownReason>,
    mode: RegisteredMode,
    authority_expires_at: Option<OffsetDateTime>,
    /// The recorded closure (empty unless `bound*`).
    closure: Arc<[Hash]>,
}

impl Binding {
    fn from_classification(classification: &Classification, mode: RegisteredMode) -> Self {
        Self {
            state: classification.state,
            reason: classification.reason,
            mode,
            authority_expires_at: classification.authority_expires_at,
            closure: classification.closure.iter().map(|(id, _)| *id).collect(),
        }
    }
}

/// The owner authority a policy use passed: the closure to watch for
/// revocation, and whether it was served under the legacy escape.
#[derive(Clone, Debug, Default)]
pub struct OwnerAuthority {
    pub closure: Arc<[Hash]>,
    pub escaped: bool,
}

/// How a registration's owner held what its roots grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classification {
    pub state: BindingState,
    pub reason: Option<UnknownReason>,
    pub authority_expires_at: Option<OffsetDateTime>,
    /// `(delegation, depth)` over the recorded closure. Empty when read back
    /// from a persisted row.
    pub closure: Vec<(Hash, u32)>,
    /// Whether this classification is stored, rather than computed for this
    /// request after its write failed.
    pub persisted: bool,
    /// Found by the register grant (design rules 1–5). Set only for the
    /// registration that computed it; never persisted, so a stored row is
    /// always `false`.
    pub register_grant: bool,
}

impl Classification {
    /// Stored and not re-evaluated on use: everything except `starved` (more
    /// candidates may fit the window later) and rows from an older
    /// classifier.
    fn is_final(&self) -> bool {
        self.persisted && self.reason != Some(UnknownReason::Starved)
    }

    fn from_selection(
        selection: Result<Vec<ClosureNode>, UnknownReason>,
        root_expiry: OffsetDateTime,
    ) -> Self {
        match selection {
            Err(reason) => Self {
                state: BindingState::Unknown,
                reason: Some(reason),
                authority_expires_at: None,
                closure: Vec::new(),
                persisted: false,
                register_grant: false,
            },
            Ok(closure) if closure.is_empty() => Self {
                state: BindingState::RootAuthority,
                reason: None,
                authority_expires_at: None,
                closure: Vec::new(),
                persisted: false,
                register_grant: false,
            },
            Ok(closure) => {
                let authority_expires_at = min_expiry(&closure);
                Self {
                    state: if covers(authority_expires_at, root_expiry) {
                        BindingState::Bound
                    } else {
                        BindingState::BoundUncapped
                    },
                    reason: None,
                    authority_expires_at,
                    closure: closure.iter().map(|node| (node.id, node.depth)).collect(),
                    persisted: false,
                    register_grant: false,
                }
            }
        }
    }

    fn unknown(reason: UnknownReason) -> Self {
        Self::from_selection(Err(reason), OffsetDateTime::UNIX_EPOCH)
    }

    /// A closure found by the register grant. Its state follows the root
    /// expiry like any closure: `BoundUncapped` means the root outlives D.
    fn from_register_grant(closure: Vec<ClosureNode>, root_expiry: OffsetDateTime) -> Self {
        Self {
            register_grant: true,
            ..Self::from_selection(Ok(closure), root_expiry)
        }
    }

    fn from_row(row: &policy_v3_owner_binding::Model) -> Result<Self, &'static str> {
        Ok(Self {
            state: BindingState::parse(&row.state).ok_or("policy-owner-binding-invalid")?,
            reason: row
                .unknown_reason
                .as_deref()
                .map(|reason| UnknownReason::parse(reason).ok_or("policy-owner-binding-invalid"))
                .transpose()?,
            authority_expires_at: row
                .authority_expires_at
                .as_deref()
                .map(|value| parse_time(value).map_err(|_| "policy-owner-binding-invalid"))
                .transpose()?,
            closure: Vec::new(),
            persisted: true,
            register_grant: false,
        })
    }
}

/// The selection failed for a reason other than missing authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SelectionUnavailable;

/// Longest a policy root may live past its registration, and the clock skew
/// allowed on top.
const MAX_ROOT_LIFETIME: Duration = Duration::days(31);
const ROOT_LIFETIME_SKEW: Duration = Duration::minutes(5);

/// The registration-time root-lifetime cap: `exp <= registered_at + 31 d
/// (+5 min)` and `nbf <= exp`. `nbf` is signer-chosen, so it doesn't anchor
/// the cap.
pub(super) fn root_lifetime_allowed(
    registered_at: OffsetDateTime,
    not_before: OffsetDateTime,
    expiry: OffsetDateTime,
) -> bool {
    not_before <= expiry && expiry <= registered_at + MAX_ROOT_LIFETIME + ROOT_LIFETIME_SKEW
}

/// The `authority_ttl_bucket` of a root that outlives its authority, by
/// how long the authority had left at registration: `le_1h` (released
/// Share, signed by a login session), `le_30d` (CLI device sessions) or
/// `gt_30d`. Only `bound-uncapped` roots are bucketed, and their authority
/// always expires.
pub(super) fn authority_ttl_bucket(
    registered_at: OffsetDateTime,
    authority_expires_at: OffsetDateTime,
) -> &'static str {
    let remaining = authority_expires_at - registered_at;
    if remaining <= Duration::hours(1) {
        "le_1h"
    } else if remaining <= Duration::days(30) {
        "le_30d"
    } else {
        "gt_30d"
    }
}

fn min_expiry(closure: &[ClosureNode]) -> Option<OffsetDateTime> {
    closure.iter().filter_map(|node| node.expiry).min()
}

fn covers(authority_expires_at: Option<OffsetDateTime>, root_expiry: OffsetDateTime) -> bool {
    authority_expires_at.is_none_or(|expiry| root_expiry <= expiry)
}

/// DIDs that can issue a delegation granting `capability` from scratch: the
/// owner of its space, or of its encryption network.
fn capability_issuers(capability: &Capability) -> Vec<String> {
    let mut issuers = Vec::new();
    if let Some(space) = capability.resource.space() {
        issuers.push(space.did().as_str().to_owned());
    }
    if let Resource::Other(uri) = &capability.resource {
        if let Ok(network) = uri.as_str().parse::<NetworkId>() {
            issuers.push(network.owner_did().to_owned());
        }
    }
    issuers
}

/// SQL prefilter for a principal column. `did:pkh` addresses compare
/// case-insensitively (checksummed and lowercase forms name one account);
/// every candidate is re-checked with `did_principal_matches`.
fn principal_condition(column: delegation_model::Column, did: &str) -> Condition {
    if did.starts_with("did:pkh:") {
        let lower = did.to_ascii_lowercase();
        Condition::any()
            .add(Expr::expr(Func::lower(Expr::col(column))).eq(lower.clone()))
            .add(Expr::expr(Func::lower(Expr::col(column))).like(format!("{lower}#%")))
    } else {
        Condition::any()
            .add(column.eq(did))
            .add(column.like(format!("{did}#%")))
    }
}

/// Ability-resource conditions for delegations touching the space or
/// encryption network `capability` targets. Only principals holding authority
/// derived from that space or network can create such rows.
fn capability_scope(capability: &Capability) -> Option<Condition> {
    let mut scope = Condition::any();
    let mut any = false;
    if let Some(space) = capability.resource.space() {
        let space = space.to_string();
        scope = scope
            .add(abilities::Column::Resource.eq(space.clone()))
            .add(abilities::Column::Resource.like(format!("{space}/%")));
        any = true;
    }
    if let Resource::Other(uri) = &capability.resource {
        if uri.as_str().parse::<NetworkId>().is_ok() {
            scope = scope.add(abilities::Column::Resource.eq(uri.as_str().to_owned()));
            any = true;
        }
    }
    any.then_some(scope)
}

fn is_policy_fact_row(row: &delegation_model::Model) -> bool {
    row.facts.as_ref().is_some_and(|facts| {
        facts.0.contains_key("xyz.tinycloud.policy/session-fact")
            || facts.0.contains_key("xyz.tinycloud.policy/root-profile")
    })
}

async fn candidate_rows<C: ConnectionTrait>(
    conn: &C,
    owner_did: &str,
    issuers: Option<&[String]>,
    scope: Option<Condition>,
    at: OffsetDateTime,
    issued_before: Option<OffsetDateTime>,
    limit: u64,
) -> Result<Vec<delegation_model::Model>, DbErr> {
    let mut query = delegation_model::Entity::find()
        .filter(
            Condition::any()
                .add(delegation_model::Column::Delegatee.eq(owner_did))
                .add(delegation_model::Column::Delegatee.like(format!("{owner_did}#%"))),
        )
        .filter(
            Condition::any()
                .add(delegation_model::Column::Expiry.is_null())
                .add(delegation_model::Column::Expiry.gt(at)),
        );
    if let Some(issuers) = issuers {
        let mut any = Condition::any();
        for issuer in issuers {
            any = any.add(principal_condition(
                delegation_model::Column::Delegator,
                issuer,
            ));
        }
        query = query.filter(any);
    }
    if let Some(scope) = scope {
        query = query.filter(
            delegation_model::Column::Id.in_subquery(
                Query::select()
                    .column(abilities::Column::Delegation)
                    .from(abilities::Entity)
                    .cond_where(scope)
                    .to_owned(),
            ),
        );
    }
    if let Some(issued_before) = issued_before {
        // UCANs carry no issue time; they cannot be ordered against the
        // registration and stay eligible, as before the binding existed.
        query = query.filter(
            Condition::any()
                .add(delegation_model::Column::IssuedAt.is_null())
                .add(delegation_model::Column::IssuedAt.lte(issued_before)),
        );
    }
    query
        .order_by_with_nulls(
            delegation_model::Column::IssuedAt,
            tinycloud_core::sea_orm::Order::Desc,
            tinycloud_core::sea_orm::sea_query::NullOrdering::Last,
        )
        .order_by_asc(delegation_model::Column::Id)
        .limit(limit)
        .all(conn)
        .await
}

struct Chosen {
    closure: Vec<ClosureNode>,
}

#[derive(Default)]
struct Attempt {
    saw_revoked: bool,
    untried: bool,
}

/// The first candidate, newest first, that satisfies `capability` and whose
/// closure outlives the root; else the first that satisfies it.
#[allow(clippy::too_many_arguments)]
async fn choose<C: ConnectionTrait>(
    conn: &C,
    owner_did: &str,
    capability: &Capability,
    rows: Vec<delegation_model::Model>,
    issuers: Option<&[String]>,
    at: OffsetDateTime,
    root_expiry: OffsetDateTime,
    max_tries: usize,
    attempt: &mut Attempt,
) -> Result<Option<Chosen>, SelectionUnavailable> {
    let mut first = None;
    let mut tried = 0;
    for row in rows.into_iter().filter(|row| !is_policy_fact_row(row)) {
        if issuers.is_some_and(|issuers| {
            !issuers
                .iter()
                .any(|issuer| did_principal_matches(&row.delegator, issuer))
        }) {
            continue;
        }
        let closure = match authority_graph::load_closure(conn, &[row.id]).await {
            Ok(closure) => closure,
            Err(ChainTraversalError::LimitExceeded) => continue,
            Err(ChainTraversalError::Db(_)) => return Err(SelectionUnavailable),
        };
        // Loop-back candidates are skipped without using up a try.
        if closure
            .iter()
            .any(|node| did_principal_matches(&node.delegator, owner_did))
        {
            continue;
        }
        if tried == max_tries {
            attempt.untried = true;
            break;
        }
        tried += 1;
        match invocation_model::authorize_holder(
            conn,
            owner_did,
            std::slice::from_ref(capability),
            &[row.id.to_cid(0x55)],
            at,
        )
        .await
        {
            Ok(()) => {
                if covers(min_expiry(&closure), root_expiry) {
                    return Ok(Some(Chosen { closure }));
                }
                if first.is_none() {
                    first = Some(Chosen { closure });
                }
            }
            Err(InvocationModelError::Db(_)) => return Err(SelectionUnavailable),
            Err(InvocationModelError::InvalidInvocation(
                InvocationError::DelegationRevoked(_)
                | InvocationError::DelegationAncestorRevoked { .. },
            )) => attempt.saw_revoked = true,
            Err(_) => {}
        }
    }
    Ok(first)
}

/// Select the owner delegations that grant `capabilities` at `at` and return
/// their merged ancestor closure: empty when every capability is held as
/// root authority, `Err(Ok(reason))` when some capability has no authority.
pub(super) async fn select_owner_authority<C: ConnectionTrait>(
    conn: &C,
    owner_did: &str,
    capabilities: &[Capability],
    at: OffsetDateTime,
    issued_before: Option<OffsetDateTime>,
    root_expiry: OffsetDateTime,
) -> Result<Result<Vec<ClosureNode>, UnknownReason>, SelectionUnavailable> {
    let mut merged: HashMap<Hash, ClosureNode> = HashMap::new();
    for capability in capabilities {
        if invocation_model::authorize_holder(
            conn,
            owner_did,
            std::slice::from_ref(capability),
            &[],
            at,
        )
        .await
        .is_ok()
        {
            continue;
        }
        let mut attempt = Attempt::default();
        let issuers = capability_issuers(capability);
        let mut chosen = None;
        if !issuers.is_empty() {
            let rows = candidate_rows(
                conn,
                owner_did,
                Some(&issuers),
                None,
                at,
                issued_before,
                OWNER_FIRST_ROWS,
            )
            .await
            .map_err(|_| SelectionUnavailable)?;
            chosen = choose(
                conn,
                owner_did,
                capability,
                rows,
                Some(&issuers),
                at,
                root_expiry,
                OWNER_FIRST_ROWS as usize,
                &mut attempt,
            )
            .await?;
        }
        if chosen.is_none() {
            let rows = candidate_rows(
                conn,
                owner_did,
                None,
                capability_scope(capability),
                at,
                issued_before,
                MAX_OWNER_AUTHORITY_ROWS,
            )
            .await
            .map_err(|_| SelectionUnavailable)?;
            if rows.len() as u64 >= MAX_OWNER_AUTHORITY_ROWS {
                attempt.untried = true;
            }
            chosen = choose(
                conn,
                owner_did,
                capability,
                rows,
                None,
                at,
                root_expiry,
                MAX_OWNER_AUTHORITY_CANDIDATES,
                &mut attempt,
            )
            .await?;
        }
        let Some(chosen) = chosen else {
            return Ok(Err(if attempt.saw_revoked {
                UnknownReason::Revoked
            } else if attempt.untried {
                UnknownReason::Starved
            } else {
                UnknownReason::Missing
            }));
        };
        for node in chosen.closure {
            match merged.get_mut(&node.id) {
                Some(existing) => existing.depth = existing.depth.min(node.depth),
                None => {
                    merged.insert(node.id, node);
                }
            }
        }
    }
    let mut closure = merged.into_values().collect::<Vec<_>>();
    closure.sort_by(|left, right| {
        (left.depth, left.id.as_ref()).cmp(&(right.depth, right.id.as_ref()))
    });
    Ok(Ok(closure))
}

/// Register-grant route (design rules 1–5): the root's whole authority is a
/// delegation D from the space owner P to `owner_did`, carrying
/// `tinycloud.policy/register` on exactly `<S>/policy/<h>`, where `h` is the
/// template digest of the root's policy. Returns D's closure, which is `{D}`.
/// Rule 6 (the root expires no later than D) is decided by the caller.
async fn select_register_grant<C: ConnectionTrait>(
    conn: &C,
    owner_did: &str,
    capabilities: &[Capability],
    policy: &Value,
    at: OffsetDateTime,
    issued_before: Option<OffsetDateTime>,
    root_expiry: OffsetDateTime,
) -> Result<Option<Vec<ClosureNode>>, SelectionUnavailable> {
    // Rule 3: one policy space S; its owner P is the root authority.
    let Some(space_id) = capabilities.iter().find_map(|cap| cap.resource.space()) else {
        return Ok(None);
    };
    let issuer = space_id.did().as_str().to_owned();
    let space = space_id.to_string();
    if !capabilities
        .iter()
        .all(|cap| rooted_at_space(cap, &space, &issuer))
    {
        return Ok(None);
    }
    let Some(digest) = register_template_digest_hex(policy) else {
        return Ok(None);
    };
    let Ok(ability) = Ability::try_from(REGISTER_ABILITY.to_owned()) else {
        return Ok(None);
    };
    let Ok(resource) = format!("{space}/policy/{digest}").parse::<Resource>() else {
        return Ok(None);
    };
    // Rule 2: D carries the register right on exactly the template resource.
    let scope = Condition::all()
        .add(abilities::Column::Resource.eq(resource.to_string()))
        .add(abilities::Column::Ability.eq(ability.clone()));
    let rows = candidate_rows(
        conn,
        owner_did,
        Some(std::slice::from_ref(&issuer)),
        Some(scope),
        at,
        issued_before,
        MAX_OWNER_AUTHORITY_ROWS,
    )
    .await
    .map_err(|_| SelectionUnavailable)?;
    let register = Capability {
        resource,
        ability,
        caveats: Default::default(),
    };
    let mut first = None;
    for row in rows.into_iter().filter(|row| !is_policy_fact_row(row)) {
        // Rule 3: D is issued by P. The owner cannot grant itself the root.
        if !did_principal_matches(&row.delegator, &issuer)
            || did_principal_matches(&row.delegator, owner_did)
        {
            continue;
        }
        let closure = match authority_graph::load_closure(conn, &[row.id]).await {
            Ok(closure) => closure,
            Err(ChainTraversalError::LimitExceeded) => continue,
            Err(ChainTraversalError::Db(_)) => return Err(SelectionUnavailable),
        };
        // Rule 4: D has no parents, so its closure is exactly {D}.
        if closure.len() != 1 || closure[0].id != row.id {
            continue;
        }
        // Rule 5: the owner holds D at `at`, and D is unrevoked.
        match invocation_model::authorize_holder(
            conn,
            owner_did,
            std::slice::from_ref(&register),
            &[row.id.to_cid(0x55)],
            at,
        )
        .await
        {
            Ok(()) => {
                if covers(min_expiry(&closure), root_expiry) {
                    return Ok(Some(closure));
                }
                if first.is_none() {
                    first = Some(closure);
                }
            }
            Err(InvocationModelError::Db(_)) => return Err(SelectionUnavailable),
            Err(_) => {}
        }
    }
    Ok(first)
}

/// Whether `capability` is rooted at the policy space `space` owned by
/// `issuer`: a space capability on `space`, or a network owned by `issuer`.
fn rooted_at_space(capability: &Capability, space: &str, issuer: &str) -> bool {
    if let Some(cap_space) = capability.resource.space() {
        return cap_space.to_string() == space;
    }
    if let Resource::Other(uri) = &capability.resource {
        if let Ok(network) = uri.as_str().parse::<NetworkId>() {
            return did_principal_matches(network.owner_did(), issuer);
        }
    }
    false
}

/// Classify a registration at `at` for the given root expiry. Ordinary
/// selection runs first; the register grant only when it finds no authority.
pub(super) async fn classify<C: ConnectionTrait>(
    conn: &C,
    owner_did: &str,
    capabilities: &[Capability],
    policy: &Value,
    at: OffsetDateTime,
    issued_before: Option<OffsetDateTime>,
    root_expiry: OffsetDateTime,
) -> Result<Classification, SelectionUnavailable> {
    match select_owner_authority(
        conn,
        owner_did,
        capabilities,
        at,
        issued_before,
        root_expiry,
    )
    .await?
    {
        Ok(closure) => Ok(Classification::from_selection(Ok(closure), root_expiry)),
        Err(reason) => Ok(
            match select_register_grant(
                conn,
                owner_did,
                capabilities,
                policy,
                at,
                issued_before,
                root_expiry,
            )
            .await?
            {
                Some(closure) => Classification::from_register_grant(closure, root_expiry),
                None => Classification::from_selection(Err(reason), root_expiry),
            },
        ),
    }
}

/// Write a classification: the binding row first, then its closure.
pub(super) async fn insert_classification<C: ConnectionTrait>(
    conn: &C,
    policy_cid: &str,
    classification: &Classification,
    mode: RegisteredMode,
    now: OffsetDateTime,
) -> Result<(), DbErr> {
    policy_v3_owner_binding::ActiveModel {
        policy_cid: Set(policy_cid.to_owned()),
        state: Set(classification.state.as_str().to_owned()),
        authority_expires_at: Set(classification.authority_expires_at.map(format_time)),
        unknown_reason: Set(classification
            .reason
            .map(|reason| reason.as_str().to_owned())),
        classifier_version: Set(CLASSIFIER_VERSION),
        registered_mode: Set(mode.as_str().to_owned()),
        created_at: Set(format_time(now)),
    }
    .insert(conn)
    .await?;
    if !classification.closure.is_empty() {
        policy_v3_owner_authority::Entity::insert_many(classification.closure.iter().map(
            |(delegation_id, depth)| policy_v3_owner_authority::ActiveModel {
                policy_cid: Set(policy_cid.to_owned()),
                delegation_id: Set(*delegation_id),
                depth: Set(i32::try_from(*depth).unwrap_or(i32::MAX)),
            },
        ))
        .exec(conn)
        .await?;
    }
    Ok(())
}

/// Where the effective legacy cutover came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CutoverSource {
    Config,
    Migration,
}

impl CutoverSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Migration => "migration",
        }
    }
}

/// Owner-authority settings and request-path bookkeeping shared by every
/// clone of the runtime.
#[derive(Default)]
pub(super) struct OwnerAuthorityState {
    configured_cutover: Option<OffsetDateTime>,
    expiry: OwnerAuthorityExpiry,
    legacy_unknown_allow: bool,
    migration_cutover: tokio::sync::OnceCell<OffsetDateTime>,
    /// Policies whose stored classification is final, with their closure.
    /// Liveness is never cached, only what to check.
    final_policies: std::sync::Mutex<HashMap<String, Binding>>,
    /// Classifications computed for a request but not (yet) final, served
    /// until the instant given, so a failed write or `starved` is not
    /// recomputed on every request.
    transient: std::sync::Mutex<HashMap<String, (Binding, tokio::time::Instant)>>,
    /// Policies with a background write running.
    in_flight: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Slots for background writes.
    background: BackgroundSlots,
    /// When each escaped policy was last logged.
    escape_logged: std::sync::Mutex<HashMap<String, tokio::time::Instant>>,
    /// Request-path classifications running, one per policy; concurrent uses
    /// of the policy wait for it and share its result.
    classifying: std::sync::Mutex<HashMap<String, Arc<tokio::sync::OnceCell<ClassifyResult>>>>,
    /// Classifications computed (tests count them).
    #[cfg(test)]
    pub(super) classifications: std::sync::atomic::AtomicUsize,
}

type ClassifyResult = Result<(Classification, RegisteredMode), &'static str>;

/// Where a use's classification came from.
enum Classified {
    /// Remembered from a classification that finished meanwhile.
    InMemory(Binding),
    /// Computed (or awaited) by this use.
    Computed(Classification, RegisteredMode),
}

/// Insert into a bounded map, clearing it when full.
fn bounded_insert<V>(map: &mut HashMap<String, V>, key: &str, value: V) {
    if map.len() >= MAX_TRACKED_POLICIES && !map.contains_key(key) {
        map.clear();
    }
    map.insert(key.to_owned(), value);
}

impl OwnerAuthorityState {
    fn cached(&self, policy_cid: &str) -> Option<Binding> {
        if let Some(binding) = self
            .final_policies
            .lock()
            .expect("owner-authority cache")
            .get(policy_cid)
        {
            return Some(binding.clone());
        }
        let mut transient = self.transient.lock().expect("owner-authority cache");
        match transient.get(policy_cid) {
            Some((binding, until)) if *until > tokio::time::Instant::now() => Some(binding.clone()),
            Some(_) => {
                transient.remove(policy_cid);
                None
            }
            None => None,
        }
    }

    fn remember_final(&self, policy_cid: &str, binding: Binding) {
        self.transient
            .lock()
            .expect("owner-authority cache")
            .remove(policy_cid);
        bounded_insert(
            &mut self.final_policies.lock().expect("owner-authority cache"),
            policy_cid,
            binding,
        );
    }

    fn remember_transient(&self, policy_cid: &str, binding: Binding) {
        bounded_insert(
            &mut self.transient.lock().expect("owner-authority cache"),
            policy_cid,
            (binding, tokio::time::Instant::now() + RETRY_BACKOFF),
        );
    }

    /// Whether this escaped use should be logged (once per policy per hour).
    fn log_escape(&self, policy_cid: &str) -> bool {
        let mut logged = self
            .escape_logged
            .lock()
            .expect("owner-authority escape log");
        let now = tokio::time::Instant::now();
        if logged
            .get(policy_cid)
            .is_some_and(|at| now.duration_since(*at) < std::time::Duration::from_secs(3600))
        {
            return false;
        }
        bounded_insert(&mut logged, policy_cid, now);
        true
    }
}

/// The recorded closure of a policy.
async fn recorded_closure<C: ConnectionTrait>(
    conn: &C,
    policy_cid: &str,
) -> Result<Vec<Hash>, DbErr> {
    policy_v3_owner_authority::Entity::find()
        .filter(policy_v3_owner_authority::Column::PolicyCid.eq(policy_cid))
        .all(conn)
        .await
        .map(|rows| rows.into_iter().map(|row| row.delegation_id).collect())
}

/// The process-wide limit on background classifications.
pub(super) struct BackgroundSlots(Arc<tokio::sync::Semaphore>);

impl Default for BackgroundSlots {
    fn default() -> Self {
        Self(Arc::new(tokio::sync::Semaphore::new(
            MAX_BACKGROUND_CLASSIFICATIONS,
        )))
    }
}

/// A running background classification: holds a slot and the policy's
/// in-flight mark, and releases both when dropped, including when the task
/// panics.
struct InFlight {
    state: Arc<OwnerAuthorityState>,
    policy_cid: String,
    _slot: tokio::sync::OwnedSemaphorePermit,
}

impl InFlight {
    /// Claim a slot and the policy's mark; `None` when the policy is
    /// already in flight, or no slot is free.
    fn claim(state: &Arc<OwnerAuthorityState>, policy_cid: &str) -> Option<Self> {
        let slot = Arc::clone(&state.background.0).try_acquire_owned().ok()?;
        let mut in_flight = state.in_flight.lock().expect("owner-authority in-flight");
        if in_flight.len() >= MAX_TRACKED_POLICIES || !in_flight.insert(policy_cid.to_owned()) {
            return None;
        }
        Some(Self {
            state: Arc::clone(state),
            policy_cid: policy_cid.to_owned(),
            _slot: slot,
        })
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if let Ok(mut in_flight) = self.state.in_flight.lock() {
            in_flight.remove(&self.policy_cid);
        }
    }
}

/// SQL form of `!row_is_final`.
fn not_final_rows() -> Condition {
    Condition::all()
        .add(policy_v3_owner_binding::Column::State.eq(BindingState::Unknown.as_str()))
        .add(
            Condition::any()
                .add(policy_v3_owner_binding::Column::ClassifierVersion.lt(CLASSIFIER_VERSION))
                .add(
                    policy_v3_owner_binding::Column::UnknownReason
                        .eq(UnknownReason::Starved.as_str()),
                ),
        )
}

/// Whether a stored row is final: not `starved`, not an `unknown` from an
/// older classifier.
fn row_is_final(row: &policy_v3_owner_binding::Model) -> bool {
    !(row.state == BindingState::Unknown.as_str()
        && (row.classifier_version < CLASSIFIER_VERSION
            || row.unknown_reason.as_deref() == Some(UnknownReason::Starved.as_str())))
}

enum LazyWrite {
    Written,
    /// Another writer stored a classification first.
    Lost(policy_v3_owner_binding::Model),
    Failed,
}

impl PolicyV3Runtime {
    /// Apply the `[policy_v3]` settings.
    pub fn with_policy_config(mut self, config: &crate::config::PolicyV3Config) -> Self {
        self.owner_authority = Arc::new(OwnerAuthorityState {
            configured_cutover: config.legacy_cutover(),
            expiry: config.owner_authority_expiry,
            legacy_unknown_allow: config.legacy_unknown_allow,
            ..OwnerAuthorityState::default()
        });
        self
    }

    /// Whether roots may outlive their authority (`record`) or not
    /// (`enforce`).
    pub fn owner_authority_expiry(&self) -> OwnerAuthorityExpiry {
        self.owner_authority.expiry
    }

    /// Registrations before this instant are legacy: the configured cutover,
    /// else the applied-at time of the binding-table migration.
    pub async fn legacy_cutover(&self) -> Result<(OffsetDateTime, CutoverSource), DbErr> {
        if let Some(configured) = self.owner_authority.configured_cutover {
            return Ok((configured, CutoverSource::Config));
        }
        let applied = self
            .owner_authority
            .migration_cutover
            .get_or_try_init(|| async {
                let seconds = authority_graph::migration_applied_at(
                    &self.conn,
                    authority_graph::OWNER_AUTHORITY_MIGRATION,
                )
                .await?
                .ok_or_else(|| {
                    DbErr::RecordNotFound(authority_graph::OWNER_AUTHORITY_MIGRATION.into())
                })?;
                OffsetDateTime::from_unix_timestamp(seconds)
                    .map_err(|error| DbErr::Custom(error.to_string()))
            })
            .await?;
        Ok((*applied, CutoverSource::Migration))
    }

    /// Log the effective legacy cutover once at boot, so a forgotten
    /// override after a rollback is visible.
    pub async fn log_owner_authority_cutover(&self) {
        match self.legacy_cutover().await {
            // Warn when the default cutover is under a day old: that is a
            // fresh migration, or a re-upgrade after a rollback that still
            // needs `policy_v3.legacy_cutover` set to the first deploy time.
            Ok((cutover, CutoverSource::Migration))
                if OffsetDateTime::now_utc() - cutover < Duration::days(1) =>
            {
                ::tracing::warn!(
                    event = "policy_owner_authority",
                    legacy_cutover = %format_time(cutover),
                    source = CutoverSource::Migration.as_str(),
                    owner_authority_expiry = self.owner_authority_expiry().as_str(),
                    "policy owner-authority legacy cutover is the binding migration's applied-at time, less than a day ago; after a rollback and re-upgrade, set policy_v3.legacy_cutover to the first deploy time"
                )
            }
            Ok((cutover, source)) => ::tracing::info!(
                event = "policy_owner_authority",
                legacy_cutover = %format_time(cutover),
                source = source.as_str(),
                owner_authority_expiry = self.owner_authority_expiry().as_str(),
                "policy owner-authority legacy cutover"
            ),
            Err(_) => ::tracing::warn!(
                event = "policy_owner_authority",
                owner_authority_expiry = self.owner_authority_expiry().as_str(),
                "policy owner-authority legacy cutover is unavailable; legacy policies are classified when it can be read"
            ),
        }
        if self.owner_authority.legacy_unknown_allow {
            ::tracing::warn!(
                event = "policy_owner_authority",
                legacy_unknown_allow = true,
                "policy_v3.legacy_unknown_allow is on: legacy policies without owner authority are served with root-only checks"
            );
        }
    }

    /// The stored classification of `registration`, classifying (and
    /// storing) it first if none is final. Used by the sweep.
    pub(super) async fn owner_binding(
        &self,
        registration: &policy_v3_registration::Model,
    ) -> Result<Classification, &'static str> {
        let existing = policy_v3_owner_binding::Entity::find_by_id(registration.policy_cid.clone())
            .one(&self.conn)
            .await
            .map_err(|_| "policy-owner-authority-unavailable")?;
        let stale = match &existing {
            Some(row) if row_is_final(row) => return Classification::from_row(row),
            Some(_) => true,
            None => false,
        };
        let (classification, mode) = self.classify_registration(registration).await?;
        Ok(self
            .store_classification(&registration.policy_cid, classification, mode, stale)
            .await)
    }

    /// Store a computed classification claim-first, count it, and remember
    /// it when final. Returns what is now in force.
    async fn store_classification(
        &self,
        policy_cid: &str,
        classification: Classification,
        mode: RegisteredMode,
        stale: bool,
    ) -> Classification {
        match self
            .store_lazy_classification(policy_cid, &classification, mode, stale)
            .await
        {
            LazyWrite::Written => {
                crate::prometheus::observe_policy_owner_binding_backfill(
                    match classification.state {
                        BindingState::Bound => "bound",
                        BindingState::BoundUncapped => "bound_uncapped",
                        BindingState::RootAuthority => "root_authority",
                        BindingState::Unknown => "unknown",
                    },
                );
                let classification = Classification {
                    persisted: true,
                    ..classification
                };
                if classification.is_final() {
                    self.owner_authority.remember_final(
                        policy_cid,
                        Binding::from_classification(&classification, mode),
                    );
                }
                classification
            }
            // The winner's closure is read on the next use.
            LazyWrite::Lost(winner) => {
                Classification::from_row(&winner).unwrap_or(Classification {
                    persisted: true,
                    ..classification
                })
            }
            LazyWrite::Failed => {
                crate::prometheus::observe_policy_owner_binding_backfill("write_failed_served");
                classification
            }
        }
    }

    /// What a use of `registration` checks. A final stored classification is
    /// loaded once (row and closure) and remembered. A policy without one is
    /// classified in the request, served from that result, and stored in the
    /// background; a result that isn't final is reused for
    /// [`RETRY_BACKOFF`] instead of recomputed.
    async fn binding_for_use(
        &self,
        registration: &policy_v3_registration::Model,
    ) -> Result<Binding, &'static str> {
        let state = &self.owner_authority;
        let policy_cid = &registration.policy_cid;
        if let Some(binding) = state.cached(policy_cid) {
            return Ok(binding);
        }
        let existing = policy_v3_owner_binding::Entity::find_by_id(policy_cid.clone())
            .one(&self.conn)
            .await
            .map_err(|_| "policy-owner-authority-unavailable")?;
        if let Some(row) = existing.as_ref().filter(|row| row_is_final(row)) {
            let classification = Classification::from_row(row)?;
            let closure = match classification.state {
                BindingState::Bound | BindingState::BoundUncapped => {
                    recorded_closure(&self.conn, policy_cid)
                        .await
                        .map_err(|_| "policy-owner-authority-unavailable")?
                }
                BindingState::RootAuthority | BindingState::Unknown => Vec::new(),
            };
            let binding = Binding {
                state: classification.state,
                reason: classification.reason,
                mode: RegisteredMode::parse(&row.registered_mode)
                    .ok_or("policy-owner-binding-invalid")?,
                authority_expires_at: classification.authority_expires_at,
                closure: closure.into(),
            };
            state.remember_final(policy_cid, binding.clone());
            return Ok(binding);
        }
        let (classification, mode) = match self.classify_once(registration).await? {
            Classified::InMemory(binding) => return Ok(binding),
            Classified::Computed(classification, mode) => (classification, mode),
        };
        let binding = Binding::from_classification(&classification, mode);
        // The write runs in the background (one per policy, a few at once).
        // Without a free slot this request still uses its result; the write
        // is retried once the in-memory result expires.
        if let Some(claim) = InFlight::claim(state, policy_cid) {
            let runtime = self.clone();
            let policy_cid = policy_cid.clone();
            let stale = existing.is_some();
            tokio::spawn(async move {
                let _claim = claim;
                runtime
                    .store_classification(&policy_cid, classification, mode, stale)
                    .await;
            });
        }
        Ok(binding)
    }

    /// Classify a policy for a use, one computation at a time per policy:
    /// concurrent uses wait for it and share its result. A result is
    /// remembered in memory before the computation's entry is dropped, and a
    /// use that finds no entry checks memory under the same lock, so a use
    /// arriving just after a computation reuses it rather than starting
    /// another. No lock is held across an await; if the computing request is
    /// cancelled, a waiting one takes over.
    async fn classify_once(
        &self,
        registration: &policy_v3_registration::Model,
    ) -> Result<Classified, &'static str> {
        let state = &self.owner_authority;
        let policy_cid = &registration.policy_cid;
        let cell = {
            let mut classifying = state
                .classifying
                .lock()
                .expect("owner-authority classifications");
            match classifying.get(policy_cid) {
                Some(cell) => cell.clone(),
                None => {
                    if let Some(binding) = state.cached(policy_cid) {
                        return Ok(Classified::InMemory(binding));
                    }
                    classifying.entry(policy_cid.clone()).or_default().clone()
                }
            }
        };
        let result = cell
            .get_or_init(|| async {
                let result = self.classify_registration(registration).await;
                if let Ok((classification, mode)) = &result {
                    state.remember_transient(
                        policy_cid,
                        Binding::from_classification(classification, *mode),
                    );
                }
                result
            })
            .await
            .clone();
        let mut classifying = state
            .classifying
            .lock()
            .expect("owner-authority classifications");
        if classifying
            .get(policy_cid)
            .is_some_and(|current| Arc::ptr_eq(current, &cell))
        {
            classifying.remove(policy_cid);
        }
        result.map(|(classification, mode)| Classified::Computed(classification, mode))
    }

    /// Check a policy use against its recorded owner authority: every
    /// recorded delegation and ancestor must be unrevoked (as of `conn`, the
    /// caller's transaction where it has one), and a `bound` authority
    /// unexpired. Legacy registrations are never expiry-checked. A policy
    /// without authority is denied, or served with root-only checks under
    /// `policy_v3.legacy_unknown_allow` when it is legacy.
    pub(super) async fn validate_owner_authority<C: ConnectionTrait>(
        &self,
        conn: &C,
        registration: &policy_v3_registration::Model,
        now: OffsetDateTime,
    ) -> Result<OwnerAuthority, &'static str> {
        let binding = self.binding_for_use(registration).await?;
        match binding.state {
            BindingState::RootAuthority => Ok(OwnerAuthority::default()),
            BindingState::Unknown => {
                let reason = binding.reason.map_or("missing", UnknownReason::as_str);
                if binding.mode == RegisteredMode::Backfill
                    && self.owner_authority.legacy_unknown_allow
                {
                    crate::prometheus::observe_policy_owner_authority_unknown_allowed(reason);
                    if self.owner_authority.log_escape(&registration.policy_cid) {
                        ::tracing::warn!(
                            event = "policy_owner_authority",
                            outcome = "unknown_allowed",
                            policy_cid = %registration.policy_cid,
                            reason,
                            "legacy policy without owner authority served under policy_v3.legacy_unknown_allow"
                        );
                    }
                    return Ok(OwnerAuthority {
                        closure: Arc::from([]),
                        escaped: true,
                    });
                }
                crate::prometheus::observe_policy_owner_authority_denied("unknown");
                Err("policy-owner-authority-unknown")
            }
            BindingState::Bound | BindingState::BoundUncapped => {
                let revoked = authority_graph::revoked_ids(conn, &binding.closure)
                    .await
                    .map_err(|_| "policy-owner-authority-unavailable")?;
                if !revoked.is_empty() {
                    crate::prometheus::observe_policy_owner_authority_denied("revoked");
                    return Err("policy-owner-authority-revoked");
                }
                if binding.state == BindingState::Bound
                    && binding.mode != RegisteredMode::Backfill
                    && binding
                        .authority_expires_at
                        .is_some_and(|expiry| now >= expiry)
                {
                    crate::prometheus::observe_policy_owner_authority_denied("expired");
                    return Err("policy-owner-authority-expired");
                }
                Ok(OwnerAuthority {
                    closure: binding.closure,
                    escaped: false,
                })
            }
        }
    }

    async fn classify_registration(
        &self,
        registration: &policy_v3_registration::Model,
    ) -> ClassifyResult {
        #[cfg(test)]
        self.owner_authority
            .classifications
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let registered_at =
            parse_time(&registration.registered_at).map_err(|_| "policy-registration-invalid")?;
        let (cutover, _) = self
            .legacy_cutover()
            .await
            .map_err(|_| "policy-owner-authority-unavailable")?;
        let mode = if registered_at < cutover {
            RegisteredMode::Backfill
        } else {
            // Registered without a binding after the cutover: by a binary
            // that predates it (a rollback window or a mixed deploy). The
            // current mode's registration rules apply.
            RegisteredMode::current(self.owner_authority_expiry())
        };
        let root = policy_v3_root::Entity::find_by_id(registration.policy_root_cid.clone())
            .one(&self.conn)
            .await
            .map_err(|_| "policy-owner-authority-unavailable")?
            .ok_or("policy-root-missing")?;
        let root = decode_delegation(
            std::str::from_utf8(&root.authorization_bytes).map_err(|_| "policy-root-invalid")?,
        )
        .map_err(|_| "policy-root-invalid")?;
        let root_expiry = root.0.expiry.ok_or("policy-root-expiry-missing")?;
        let root_not_before = root.0.not_before.ok_or("policy-root-invalid")?;
        let lifetime_allowed = root_lifetime_allowed(registered_at, root_not_before, root_expiry);
        if mode != RegisteredMode::Backfill && !lifetime_allowed {
            return Ok((
                Classification::unknown(UnknownReason::LifetimeExceeded),
                mode,
            ));
        }
        let policy: Value = serde_json::from_slice(&registration.policy_bytes)
            .map_err(|_| "policy-registration-corrupt")?;
        // As the mint check always has: the authority the owner held when
        // it registered, revoked as of now.
        let mut classification = classify(
            &self.conn,
            &registration.owner_did,
            &root.0.capabilities,
            &policy,
            registered_at,
            Some(registered_at),
            root_expiry,
        )
        .await
        .map_err(|_| "policy-owner-authority-unavailable")?;
        // Design rule 6 in the background: a register-grant root that outlives
        // its grant is unknown in both modes, never bound uncapped.
        if classification.register_grant && classification.state == BindingState::BoundUncapped {
            classification = Classification::unknown(UnknownReason::OutlivesAuthority);
        }
        match mode {
            // Legacy roots longer than the cap are counted, never refused.
            RegisteredMode::Backfill if !lifetime_allowed => {
                crate::prometheus::observe_policy_legacy_root_lifetime_exceeded();
            }
            RegisteredMode::Enforce if classification.state == BindingState::BoundUncapped => {
                classification = Classification::unknown(UnknownReason::OutlivesAuthority);
            }
            _ => {}
        }
        Ok((classification, mode))
    }

    async fn store_lazy_classification(
        &self,
        policy_cid: &str,
        classification: &Classification,
        mode: RegisteredMode,
        stale: bool,
    ) -> LazyWrite {
        let _writer = match &self.sqlite_writer_lock {
            Some(lock) => match tokio::time::timeout(LAZY_WRITE_LOCK_WAIT, lock.lock()).await {
                Ok(guard) => Some(guard),
                Err(_) => return LazyWrite::Failed,
            },
            None => None,
        };
        let Ok(txn) = tinycloud_core::db::begin_write_transaction(&self.conn, None).await else {
            return LazyWrite::Failed;
        };
        let written = async {
            if stale {
                let claimed = policy_v3_owner_binding::Entity::delete_many()
                    .filter(policy_v3_owner_binding::Column::PolicyCid.eq(policy_cid))
                    .filter(not_final_rows())
                    .exec(&txn)
                    .await?;
                if claimed.rows_affected == 0 {
                    return Err(DbErr::RecordNotUpdated);
                }
                policy_v3_owner_authority::Entity::delete_many()
                    .filter(policy_v3_owner_authority::Column::PolicyCid.eq(policy_cid))
                    .exec(&txn)
                    .await?;
            }
            insert_classification(
                &txn,
                policy_cid,
                classification,
                mode,
                OffsetDateTime::now_utc(),
            )
            .await
        }
        .await;
        if written.is_ok() && txn.commit().await.is_ok() {
            return LazyWrite::Written;
        }
        // The transaction rolled back (on drop, if not already). A concurrent
        // writer that stored first wins; anything else is a write failure.
        match policy_v3_owner_binding::Entity::find_by_id(policy_cid.to_owned())
            .one(&self.conn)
            .await
        {
            Ok(Some(winner)) if row_is_final(&winner) => LazyWrite::Lost(winner),
            _ => {
                ::tracing::warn!(
                    event = "policy_owner_authority",
                    outcome = "write_failed_served",
                    "policy owner-authority classification could not be stored; served from memory"
                );
                LazyWrite::Failed
            }
        }
    }

    /// Classify up to `limit` registrations with no current classification,
    /// after `after` in policy-CID order. Returns the last policy CID seen
    /// and how many were classified.
    pub async fn backfill_owner_bindings_page(
        &self,
        after: Option<&str>,
        limit: u64,
    ) -> Result<(Option<String>, Vec<String>), DbErr> {
        let classified = Query::select()
            .column(policy_v3_owner_binding::Column::PolicyCid)
            .from(policy_v3_owner_binding::Entity)
            .cond_where(not_final_rows().not())
            .to_owned();
        let mut query = policy_v3_registration::Entity::find()
            .filter(policy_v3_registration::Column::PolicyCid.not_in_subquery(classified))
            .order_by_asc(policy_v3_registration::Column::PolicyCid)
            .limit(limit);
        if let Some(after) = after {
            query = query.filter(policy_v3_registration::Column::PolicyCid.gt(after));
        }
        let page = query.all(&self.conn).await?;
        let last = page.last().map(|row| row.policy_cid.clone());
        Ok((last, page.into_iter().map(|row| row.policy_cid).collect()))
    }

    /// Classify one registration for the sweep. Errors are counted, not
    /// raised: the lazy path classifies it on first use anyway.
    pub async fn backfill_owner_binding(&self, policy_cid: &str) -> Result<bool, DbErr> {
        let Some(registration) = policy_v3_registration::Entity::find_by_id(policy_cid.to_owned())
            .one(&self.conn)
            .await?
        else {
            return Ok(false);
        };
        Ok(self
            .owner_binding(&registration)
            .await
            .is_ok_and(|classification| classification.persisted))
    }
}

/// Run the owner-binding sweep until every pending registration has been
/// visited once or the node shuts down. `config` is validated.
pub async fn run_owner_binding_backfill(
    runtime: &PolicyV3Runtime,
    config: &crate::config::OwnerBindingBackfillConfig,
    shutdown: impl Future<Output = ()>,
) -> (u64, u64) {
    tokio::pin!(shutdown);
    let interval = std::time::Duration::from_secs(1) / config.policies_per_second.max(1);
    let (mut visited, mut stored) = (0u64, 0u64);
    let mut after: Option<String> = None;
    ::tracing::info!(
        event = "policy_owner_binding_backfill",
        phase = "start",
        policies_per_second = config.policies_per_second,
        "policy owner-binding sweep started"
    );
    loop {
        let (last, page) = match runtime
            .backfill_owner_bindings_page(after.as_deref(), 100)
            .await
        {
            Ok(page) => page,
            Err(_) => {
                ::tracing::error!(
                    event = "policy_owner_binding_backfill",
                    phase = "stopped",
                    visited,
                    stored,
                    "policy owner-binding sweep stopped at its first error; policies are still classified on first use"
                );
                return (visited, stored);
            }
        };
        if page.is_empty() {
            ::tracing::info!(
                event = "policy_owner_binding_backfill",
                phase = "done",
                visited,
                stored,
                "policy owner-binding sweep finished"
            );
            return (visited, stored);
        }
        for policy_cid in page {
            let started = tokio::time::Instant::now();
            visited += 1;
            if runtime
                .backfill_owner_binding(&policy_cid)
                .await
                .unwrap_or(false)
            {
                stored += 1;
            }
            let pause = interval.max(started.elapsed());
            tokio::select! {
                _ = &mut shutdown => return (visited, stored),
                _ = tokio::time::sleep(pause) => {}
            }
        }
        after = last;
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizedPoliciesRequest {
    pub cid: String,
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Policies whose recorded owner authority includes `cid`: the delegation
/// itself or any descendant of it the owner held. Authorized like
/// `/delegation/status` on `urn:cid:<cid>`. Policies not yet classified are
/// not listed. Keyset-paginated by policy CID, no total count.
#[post("/policy/v3/authorized", format = "json", data = "<request>")]
pub async fn authorized_policies(
    invocation: AuthHeaderGetter<InvocationInfo>,
    request: Json<AuthorizedPoliciesRequest>,
    tinycloud: &State<crate::TinyCloud>,
    runtime: &State<PolicyV3Runtime>,
) -> Result<Json<Value>, (Status, String)> {
    let request = request.into_inner();
    let auth = &invocation.0 .0;
    invocation_model::verify_invocation(&auth.invocation)
        .await
        .map_err(|_| (Status::Unauthorized, "invocation-invalid".to_string()))?;
    let expected_resource = format!("urn:cid:{}", request.cid);
    let bound = auth.capabilities.len() == 1
        && auth.capabilities.iter().all(|capability| {
            capability.ability.as_ref().as_ref() == "tinycloud.delegation/status"
                && matches!(
                    &capability.resource,
                    Resource::Other(resource) if resource.as_str() == expected_resource
                )
        });
    if !bound {
        return Err((
            Status::Forbidden,
            "policy-listing-invocation-unbound".to_string(),
        ));
    }
    let cid: tinycloud_auth::ipld_core::cid::Cid = request
        .cid
        .parse()
        .map_err(|_| (Status::BadRequest, "cid-invalid".to_string()))?;
    let target = Hash::from(cid);
    match tinycloud
        .delegation_status(target, &auth.invoker, &auth.parents)
        .await
        .map_err(|_| {
            (
                Status::ServiceUnavailable,
                "policy-listing-unavailable".to_string(),
            )
        })? {
        None => {
            return Err((
                Status::Forbidden,
                "policy-listing-not-authorized".to_string(),
            ))
        }
        Some(tinycloud_core::db::DelegationStatus::Unavailable) => {
            return Err((
                Status::ServiceUnavailable,
                "policy-listing-unavailable".to_string(),
            ))
        }
        Some(_) => {}
    }
    let after = request
        .cursor
        .as_deref()
        .map(|cursor| {
            decode_config(cursor, URL_SAFE_NO_PAD)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .ok_or((Status::BadRequest, "cursor-invalid".to_string()))
        })
        .transpose()?;
    let conn = &runtime.conn;
    let ids = authority_graph::equivalent_ids(conn, target)
        .await
        .map_err(listing_unavailable)?;
    let mut page_query = policy_v3_owner_authority::Entity::find()
        .select_only()
        .column(policy_v3_owner_authority::Column::PolicyCid)
        .distinct()
        .filter(policy_v3_owner_authority::Column::DelegationId.is_in(ids))
        .order_by_asc(policy_v3_owner_authority::Column::PolicyCid)
        .limit(LISTING_PAGE);
    if let Some(after) = &after {
        page_query = page_query.filter(policy_v3_owner_authority::Column::PolicyCid.gt(after));
    }
    let policy_cids: Vec<String> = page_query
        .into_tuple()
        .all(conn)
        .await
        .map_err(listing_unavailable)?;
    let registrations: HashMap<String, policy_v3_registration::Model> =
        policy_v3_registration::Entity::find()
            .filter(policy_v3_registration::Column::PolicyCid.is_in(policy_cids.clone()))
            .all(conn)
            .await
            .map_err(listing_unavailable)?
            .into_iter()
            .map(|row| (row.policy_cid.clone(), row))
            .collect();
    let bindings: HashMap<String, policy_v3_owner_binding::Model> =
        policy_v3_owner_binding::Entity::find()
            .filter(policy_v3_owner_binding::Column::PolicyCid.is_in(policy_cids.clone()))
            .all(conn)
            .await
            .map_err(listing_unavailable)?
            .into_iter()
            .map(|row| (row.policy_cid.clone(), row))
            .collect();
    let root_cids = registrations
        .values()
        .flat_map(|row| {
            [
                row.policy_root_cid.clone(),
                row.enforcement_root_cid.clone(),
            ]
        })
        .collect::<Vec<_>>();
    let roots: HashMap<String, policy_v3_root::Model> = policy_v3_root::Entity::find()
        .filter(policy_v3_root::Column::RootCid.is_in(root_cids.clone()))
        .all(conn)
        .await
        .map_err(listing_unavailable)?
        .into_iter()
        .map(|row| (row.root_cid.clone(), row))
        .collect();
    let root_hashes = root_cids
        .iter()
        .filter_map(|cid| tinycloud_auth::ipld_core::cid::Cid::try_from(cid.as_str()).ok())
        .map(Hash::from)
        .collect::<Vec<_>>();
    let generically_revoked = authority_graph::revoked_ids(conn, &root_hashes)
        .await
        .map_err(listing_unavailable)?;
    // Live owner-authority state: a recorded closure with a revoked member
    // is `revoked`; a non-legacy `bound` authority past its expiry `expired`.
    let mut closures: HashMap<String, Vec<Hash>> = HashMap::new();
    for row in policy_v3_owner_authority::Entity::find()
        .filter(policy_v3_owner_authority::Column::PolicyCid.is_in(policy_cids.clone()))
        .all(conn)
        .await
        .map_err(listing_unavailable)?
    {
        closures
            .entry(row.policy_cid)
            .or_default()
            .push(row.delegation_id);
    }
    let closure_ids = closures.values().flatten().copied().collect::<Vec<_>>();
    let revoked_authority = authority_graph::revoked_ids(conn, &closure_ids)
        .await
        .map_err(listing_unavailable)?;
    let now = OffsetDateTime::now_utc();
    let mut policies = Vec::with_capacity(policy_cids.len());
    for policy_cid in &policy_cids {
        let Some(registration) = registrations.get(policy_cid) else {
            continue;
        };
        let revoked = [
            &registration.policy_root_cid,
            &registration.enforcement_root_cid,
        ]
        .into_iter()
        .any(|cid| {
            roots.get(cid).is_none_or(|root| root.revoked_at.is_some())
                || tinycloud_auth::ipld_core::cid::Cid::try_from(cid.as_str())
                    .is_ok_and(|parsed| generically_revoked.contains(&Hash::from(parsed)))
        });
        let expired = parse_time(&registration.expires_at).is_ok_and(|expiry| expiry <= now);
        policies.push(serde_json::json!({
            "policyCid": registration.policy_cid,
            "policyRootCid": registration.policy_root_cid,
            "enforcementRootCid": registration.enforcement_root_cid,
            "registeredAt": registration.registered_at,
            "expiresAt": registration.expires_at,
            "rootState": if revoked { "revoked" } else if expired { "expired" } else { "active" },
            "ownerAuthorityState": bindings
                .get(policy_cid)
                .map(|binding| {
                    if closures.get(policy_cid).is_some_and(|closure| {
                        closure.iter().any(|id| revoked_authority.contains(id))
                    }) {
                        "revoked"
                    } else if binding.state == BindingState::Bound.as_str()
                        && binding.registered_mode != RegisteredMode::Backfill.as_str()
                        && binding
                            .authority_expires_at
                            .as_deref()
                            .and_then(|value| parse_time(value).ok())
                            .is_some_and(|expiry| expiry <= now)
                    {
                        "expired"
                    } else {
                        binding.state.as_str()
                    }
                })
                .unwrap_or("pending"),
        }));
    }
    let next_cursor = (policy_cids.len() as u64 == LISTING_PAGE)
        .then(|| policy_cids.last())
        .flatten()
        .map(|last| encode_config(last.as_bytes(), URL_SAFE_NO_PAD));
    Ok(Json(serde_json::json!({
        "policies": policies,
        "nextCursor": next_cursor,
    })))
}

fn listing_unavailable(_: DbErr) -> (Status, String) {
    (
        Status::ServiceUnavailable,
        "policy-listing-unavailable".to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tinycloud_core::{
        migrations::Migrator,
        sea_orm::{ConnectOptions, Database},
        sea_orm_migration::MigratorTrait,
    };

    async fn counted_runtime() -> (PolicyV3Runtime, Arc<AtomicUsize>) {
        let mut db = Database::connect(ConnectOptions::new("sqlite::memory:".to_owned()))
            .await
            .unwrap();
        Migrator::up(&db, None).await.unwrap();
        let queries = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&queries);
        db.set_metric_callback(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        let runtime = PolicyV3Runtime::new(
            db,
            "did:key:z6MkNode",
            StaticSecret::new(vec![7; 32]).unwrap(),
        );
        (runtime, queries)
    }

    async fn registration(
        runtime: &PolicyV3Runtime,
        policy_cid: &str,
    ) -> policy_v3_registration::Model {
        policy_v3_registration::ActiveModel {
            policy_cid: Set(policy_cid.to_owned()),
            policy_bytes: Set(b"{}".to_vec()),
            policy_digest_hex: Set("00".into()),
            owner_did: Set("did:key:z6MkOwner".into()),
            policy_root_cid: Set(format!("{policy_cid}-root")),
            enforcement_root_cid: Set(format!("{policy_cid}-enforcement")),
            content_source_digest_hex: Set("00".into()),
            native_projection_hash_hex: Set("00".into()),
            attested_enforcer_binding_bytes: Set(b"{}".to_vec()),
            registered_at: Set(format_time(OffsetDateTime::now_utc())),
            expires_at: Set(format_time(OffsetDateTime::now_utc() + Duration::days(1))),
        }
        .insert(&runtime.conn)
        .await
        .unwrap()
    }

    async fn store(runtime: &PolicyV3Runtime, policy_cid: &str, classification: &Classification) {
        insert_classification(
            &runtime.conn,
            policy_cid,
            classification,
            RegisteredMode::Record,
            OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
    }

    /// A background write that panics releases its policy and
    /// its slot.
    #[tokio::test]
    async fn a_panicking_classification_releases_its_claim() {
        let (runtime, _) = counted_runtime().await;
        let claim = InFlight::claim(&runtime.owner_authority, "policy-panics").unwrap();
        let result = tokio::spawn(async move {
            let _claim = claim;
            panic!("classification failed");
        })
        .await;
        assert!(result.unwrap_err().is_panic());
        assert!(runtime.owner_authority.in_flight.lock().unwrap().is_empty());
        assert_eq!(
            runtime.owner_authority.background.0.available_permits(),
            MAX_BACKGROUND_CLASSIFICATIONS
        );
    }

    /// Once a final classification is loaded, a use costs one revocation
    /// query for a recorded closure and nothing for root authority.
    #[tokio::test]
    async fn steady_state_checks_cost_one_query_or_none() {
        let (runtime, queries) = counted_runtime().await;
        let now = OffsetDateTime::now_utc();
        let root_authority = registration(&runtime, "policy-root-authority").await;
        store(
            &runtime,
            &root_authority.policy_cid,
            &Classification::from_selection(Ok(Vec::new()), now),
        )
        .await;
        let bound = registration(&runtime, "policy-bound").await;
        let closure = vec![ClosureNode {
            id: tinycloud_core::hash::hash(b"grant"),
            depth: 0,
            delegator: "did:key:z6MkGrantor".into(),
            expiry: None,
            not_before: None,
        }];
        store(
            &runtime,
            &bound.policy_cid,
            &Classification::from_selection(Ok(closure), now),
        )
        .await;
        for (registration, steady_queries) in [(&root_authority, 0), (&bound, 1)] {
            runtime
                .validate_owner_authority(&runtime.conn, registration, now)
                .await
                .unwrap();
            for _ in 0..5 {
                let before = queries.load(Ordering::SeqCst);
                runtime
                    .validate_owner_authority(&runtime.conn, registration, now)
                    .await
                    .unwrap();
                assert_eq!(
                    queries.load(Ordering::SeqCst) - before,
                    steady_queries,
                    "{}",
                    registration.policy_cid
                );
            }
        }
    }

    /// An `unknown` legacy classification is denied with a fixed code, or
    /// served (escaped) when the operator allows it.
    #[tokio::test]
    async fn unknown_legacy_classifications_are_denied_unless_allowed() {
        for allow in [false, true] {
            let (runtime, _) = counted_runtime().await;
            let runtime = runtime.with_policy_config(&crate::config::PolicyV3Config {
                legacy_unknown_allow: allow,
                ..Default::default()
            });
            let registration = registration(&runtime, "policy-unknown").await;
            insert_classification(
                &runtime.conn,
                &registration.policy_cid,
                &Classification::unknown(UnknownReason::Missing),
                RegisteredMode::Backfill,
                OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();
            let result = runtime
                .validate_owner_authority(&runtime.conn, &registration, OffsetDateTime::now_utc())
                .await;
            if allow {
                assert!(result.unwrap().escaped);
            } else {
                assert_eq!(result.unwrap_err(), "policy-owner-authority-unknown");
            }
        }
    }

    /// A `bound` (non-legacy) authority that has expired is denied with the
    /// expiry code; a legacy one is not expiry-checked.
    #[tokio::test]
    async fn expired_bound_authority_is_denied_except_legacy() {
        for (mode, expected) in [
            (
                RegisteredMode::Record,
                Err("policy-owner-authority-expired"),
            ),
            (RegisteredMode::Backfill, Ok(())),
        ] {
            let (runtime, _) = counted_runtime().await;
            let registration = registration(&runtime, "policy-expiring").await;
            let expiry = OffsetDateTime::now_utc() + Duration::seconds(5);
            let closure = vec![ClosureNode {
                id: tinycloud_core::hash::hash(b"short-grant"),
                depth: 0,
                delegator: "did:key:z6MkGrantor".into(),
                expiry: Some(expiry),
                not_before: None,
            }];
            insert_classification(
                &runtime.conn,
                &registration.policy_cid,
                &Classification::from_selection(Ok(closure), expiry),
                mode,
                OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();
            let result = runtime
                .validate_owner_authority(
                    &runtime.conn,
                    &registration,
                    expiry + Duration::seconds(1),
                )
                .await
                .map(|_| ());
            assert_eq!(result, expected, "{mode:?}");
        }
    }

    /// The cap is exact: registration + 31 days + 5 minutes is accepted, one
    /// second more is refused; `nbf` may equal `exp` but not pass it.
    #[test]
    fn root_lifetime_cap_boundaries_are_exact() {
        let registered_at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let cap = registered_at + Duration::days(31) + Duration::minutes(5);
        assert!(root_lifetime_allowed(registered_at, registered_at, cap));
        assert!(!root_lifetime_allowed(
            registered_at,
            registered_at,
            cap + Duration::seconds(1)
        ));
        assert!(root_lifetime_allowed(registered_at, cap, cap));
        assert!(!root_lifetime_allowed(
            registered_at,
            cap,
            cap - Duration::seconds(1)
        ));
    }

    /// The flip signal's buckets: exactly one hour left is `le_1h`, one
    /// second more `le_30d`; exactly 30 days `le_30d`, one second more
    /// `gt_30d`.
    #[test]
    fn authority_ttl_bucket_edges_are_exact() {
        let at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        for (remaining, bucket) in [
            (Duration::seconds(90), "le_1h"),
            (Duration::hours(1), "le_1h"),
            (Duration::hours(1) + Duration::seconds(1), "le_30d"),
            (Duration::days(30), "le_30d"),
            (Duration::days(30) + Duration::seconds(1), "gt_30d"),
        ] {
            assert_eq!(
                authority_ttl_bucket(at, at + remaining),
                bucket,
                "{remaining}"
            );
        }
    }
}
