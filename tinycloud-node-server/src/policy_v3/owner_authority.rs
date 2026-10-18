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
use std::collections::HashMap;
use std::future::Future;
use tinycloud_core::{
    encryption_network::NetworkId,
    hash::Hash,
    models::{
        invocation::{Error as InvocationModelError, InvocationError},
        policy_v3_owner_authority, policy_v3_owner_binding,
    },
    policy_owner_authority::{self as authority_graph, ChainTraversalError, ClosureNode},
    sea_orm::{
        sea_query::{Func, Query},
        DbErr,
    },
    types::Resource,
    util::Capability,
};

/// Bump when classification rules change: `unknown` rows written by an
/// older version are classified again on their next use.
pub(super) const CLASSIFIER_VERSION: i32 = 1;
/// Owner-first rows examined per capability (step 1).
const OWNER_FIRST_ROWS: u64 = 64;
/// Listing page size.
const LISTING_PAGE: u64 = 100;
/// How long a lazy classification waits for the SQLite writer before it
/// serves its in-memory result instead.
const LAZY_WRITE_LOCK_WAIT: std::time::Duration = std::time::Duration::from_millis(250);

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
}

impl UnknownReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Revoked => "revoked",
            Self::Missing => "missing",
            Self::Starved => "starved",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "revoked" => Self::Revoked,
            "missing" => Self::Missing,
            "starved" => Self::Starved,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisteredMode {
    /// Classified at registration, without refusing roots that outlive
    /// their authority.
    Record,
    /// Classified after registration, for a policy registered before the
    /// legacy cutover.
    Backfill,
}

impl RegisteredMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Record => "record",
            Self::Backfill => "backfill",
        }
    }
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
}

impl Classification {
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
            },
            Ok(closure) if closure.is_empty() => Self {
                state: BindingState::RootAuthority,
                reason: None,
                authority_expires_at: None,
                closure: Vec::new(),
                persisted: false,
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
                }
            }
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
        })
    }
}

/// The selection failed for a reason other than missing authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SelectionUnavailable;

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
        if tried == max_tries {
            attempt.untried = true;
            break;
        }
        tried += 1;
        let closure = match authority_graph::load_closure(conn, &[row.id]).await {
            Ok(closure) => closure,
            Err(ChainTraversalError::LimitExceeded) => continue,
            Err(ChainTraversalError::Db(_)) => return Err(SelectionUnavailable),
        };
        if closure
            .iter()
            .any(|node| did_principal_matches(&node.delegator, owner_did))
        {
            continue;
        }
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

/// Classify a registration at `at` for the given root expiry.
pub(super) async fn classify<C: ConnectionTrait>(
    conn: &C,
    owner_did: &str,
    capabilities: &[Capability],
    at: OffsetDateTime,
    issued_before: Option<OffsetDateTime>,
    root_expiry: OffsetDateTime,
) -> Result<Classification, SelectionUnavailable> {
    let selection = select_owner_authority(
        conn,
        owner_did,
        capabilities,
        at,
        issued_before,
        root_expiry,
    )
    .await?;
    Ok(Classification::from_selection(selection, root_expiry))
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

/// Owner-authority settings shared by every clone of the runtime.
#[derive(Default)]
pub(super) struct OwnerAuthorityState {
    configured_cutover: Option<OffsetDateTime>,
    migration_cutover: tokio::sync::OnceCell<OffsetDateTime>,
    #[cfg(test)]
    pub(super) fail_lazy_writes: std::sync::atomic::AtomicBool,
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
            ..OwnerAuthorityState::default()
        });
        self
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
            Ok((cutover, source)) => ::tracing::info!(
                event = "policy_owner_authority",
                legacy_cutover = %format_time(cutover),
                source = source.as_str(),
                "policy owner-authority legacy cutover"
            ),
            Err(_) => ::tracing::warn!(
                event = "policy_owner_authority",
                "policy owner-authority legacy cutover is unavailable; legacy policies are classified when it can be read"
            ),
        }
    }

    /// The stored classification of `registration`, classifying it first if
    /// none is stored (or a stored `unknown` came from an older classifier).
    /// A classification that cannot be stored is still returned, unstored.
    pub(super) async fn owner_binding(
        &self,
        registration: &policy_v3_registration::Model,
    ) -> Result<Classification, &'static str> {
        let existing = policy_v3_owner_binding::Entity::find_by_id(registration.policy_cid.clone())
            .one(&self.conn)
            .await
            .map_err(|_| "policy-owner-authority-unavailable")?;
        let stale = match &existing {
            Some(row)
                if row.state == BindingState::Unknown.as_str()
                    && row.classifier_version < CLASSIFIER_VERSION =>
            {
                true
            }
            Some(row) => return Classification::from_row(row),
            None => false,
        };
        let (classification, mode) = self.classify_registration(registration).await?;
        match self
            .store_lazy_classification(&registration.policy_cid, &classification, mode, stale)
            .await
        {
            LazyWrite::Written => Ok(Classification {
                persisted: true,
                ..classification
            }),
            LazyWrite::Lost(winner) => Classification::from_row(&winner),
            LazyWrite::Failed => Ok(classification),
        }
    }

    async fn classify_registration(
        &self,
        registration: &policy_v3_registration::Model,
    ) -> Result<(Classification, RegisteredMode), &'static str> {
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
            // that predates it (a rollback window or a mixed deploy).
            RegisteredMode::Record
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
        // As the mint check always has: the authority the owner held when
        // it registered, revoked as of now.
        let classification = classify(
            &self.conn,
            &registration.owner_did,
            &root.0.capabilities,
            registered_at,
            Some(registered_at),
            root_expiry,
        )
        .await
        .map_err(|_| "policy-owner-authority-unavailable")?;
        Ok((classification, mode))
    }

    async fn store_lazy_classification(
        &self,
        policy_cid: &str,
        classification: &Classification,
        mode: RegisteredMode,
        stale: bool,
    ) -> LazyWrite {
        #[cfg(test)]
        if self
            .owner_authority
            .fail_lazy_writes
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return LazyWrite::Failed;
        }
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
                    .filter(
                        policy_v3_owner_binding::Column::State.eq(BindingState::Unknown.as_str()),
                    )
                    .filter(
                        policy_v3_owner_binding::Column::ClassifierVersion.lt(CLASSIFIER_VERSION),
                    )
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
            Ok(Some(winner))
                if !(winner.state == BindingState::Unknown.as_str()
                    && winner.classifier_version < CLASSIFIER_VERSION) =>
            {
                LazyWrite::Lost(winner)
            }
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
            .cond_where(
                Condition::any()
                    .add(policy_v3_owner_binding::Column::State.ne(BindingState::Unknown.as_str()))
                    .add(
                        policy_v3_owner_binding::Column::ClassifierVersion.gte(CLASSIFIER_VERSION),
                    ),
            )
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
        .map_err(db_error)?;
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
    let policy_cids: Vec<String> = page_query.into_tuple().all(conn).await.map_err(db_error)?;
    let registrations: HashMap<String, policy_v3_registration::Model> =
        policy_v3_registration::Entity::find()
            .filter(policy_v3_registration::Column::PolicyCid.is_in(policy_cids.clone()))
            .all(conn)
            .await
            .map_err(db_error)?
            .into_iter()
            .map(|row| (row.policy_cid.clone(), row))
            .collect();
    let bindings: HashMap<String, policy_v3_owner_binding::Model> =
        policy_v3_owner_binding::Entity::find()
            .filter(policy_v3_owner_binding::Column::PolicyCid.is_in(policy_cids.clone()))
            .all(conn)
            .await
            .map_err(db_error)?
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
        .map_err(db_error)?
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
        .map_err(db_error)?;
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
                .map(|binding| binding.state.as_str())
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
