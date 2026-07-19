use super::*;
use crate::models::{policy_challenge, policy_delegation, policy_edge, policy_issuance_audit};
use sea_orm::{
    sea_query::Expr, ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection,
    DatabaseTransaction, DbBackend, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set,
    TransactionTrait,
};

#[derive(Clone)]
pub struct DatabaseAuthorityStore {
    db: DatabaseConnection,
    chain_locks: Arc<tokio::sync::Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>>,
    #[cfg(test)]
    race_barrier: Option<Arc<tokio::sync::Barrier>>,
}

impl DatabaseAuthorityStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            chain_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            #[cfg(test)]
            race_barrier: None,
        }
    }

    #[cfg(test)]
    pub(super) fn with_race_barrier_for_test(mut self, barrier: Arc<tokio::sync::Barrier>) -> Self {
        self.race_barrier = Some(barrier);
        self
    }

    #[cfg(test)]
    async fn wait_at_race_barrier(&self) {
        if self.db.get_database_backend() == DbBackend::Sqlite {
            if let Some(barrier) = &self.race_barrier {
                barrier.wait().await;
            }
        }
    }

    pub async fn insert_verified_authority(
        &self,
        artifact: VerifiedDelegation,
        status: AuthorityStatus,
    ) -> Result<(), AuthorityError> {
        policy_delegation::Entity::insert(artifact_model(&artifact, &status)?)
            .exec(&self.db)
            .await
            .map_err(|_| AuthorityError::TransactionFailed)?;
        Ok(())
    }

    /// Admit one cryptographically verified parent on the caller's
    /// transaction. Re-admission is idempotent only for byte-identical
    /// artifacts; a CID collision or a different artifact is a hard failure.
    pub async fn admit_verified_authority_in_transaction(
        &self,
        transaction: &DatabaseTransaction,
        artifact: VerifiedDelegation,
        observation: &AuthorityStatusObservation,
        now: OffsetDateTime,
    ) -> Result<(), AuthorityError> {
        let cid = artifact.0.delegation_cid.clone();
        if let Some(row) = policy_delegation::Entity::find_by_id(cid.clone())
            .one(transaction)
            .await
            .map_err(|_| AuthorityError::TransactionFailed)?
        {
            if artifact_from_model(&row)? != artifact.0 {
                return Err(AuthorityError::AuthorityStateUnavailable);
            }
            return self
                .apply_status_in_transaction(transaction, &cid, observation, now)
                .await;
        }
        if observation.checked_at > now
            || observation.fresh_until <= now
            || now - observation.checked_at > time::Duration::seconds(MAX_STATUS_AGE_SECONDS)
        {
            return Err(AuthorityError::AuthorityStateUnavailable);
        }
        let status = AuthorityStatus {
            checked_at: observation.checked_at,
            fresh_until: observation.fresh_until,
            sequence: observation.sequence,
            revoked_at: observation.revoked_at,
        };
        policy_delegation::Entity::insert(artifact_model(&artifact, &status)?)
            .exec(transaction)
            .await
            .map_err(|_| AuthorityError::TransactionFailed)?;
        Ok(())
    }

    pub async fn insert_challenge(&self, challenge: ChallengeState) -> Result<(), AuthorityError> {
        validate_challenge_lifetime(&challenge)?;
        let stored = StoredChallenge::try_from(&challenge)?;
        policy_challenge::ActiveModel {
            challenge_id: Set(challenge.challenge_id),
            challenge_json: Set(
                serde_json::to_value(stored).map_err(|_| AuthorityError::SchemaInvalid)?
            ),
            nonce_hash_hex: Set(challenge.nonce_hash_hex),
            issued_at: Set(db_time(challenge.issued_at)?),
            expires_at: Set(db_time(challenge.expires_at)?),
            consumed_at: Set(challenge.consumed_at.map(db_time).transpose()?),
        }
        .insert(&self.db)
        .await
        .map_err(|_| AuthorityError::TransactionFailed)?;
        Ok(())
    }

    pub async fn insert_challenge_in_transaction(
        &self,
        transaction: &DatabaseTransaction,
        challenge: ChallengeState,
    ) -> Result<(), AuthorityError> {
        validate_challenge_lifetime(&challenge)?;
        let stored = StoredChallenge::try_from(&challenge)?;
        policy_challenge::ActiveModel {
            challenge_id: Set(challenge.challenge_id),
            challenge_json: Set(
                serde_json::to_value(stored).map_err(|_| AuthorityError::SchemaInvalid)?
            ),
            nonce_hash_hex: Set(challenge.nonce_hash_hex),
            issued_at: Set(db_time(challenge.issued_at)?),
            expires_at: Set(db_time(challenge.expires_at)?),
            consumed_at: Set(None),
        }
        .insert(transaction)
        .await
        .map_err(|_| AuthorityError::TransactionFailed)?;
        Ok(())
    }

    pub async fn set_status(
        &self,
        cid: &str,
        status: AuthorityStatus,
    ) -> Result<(), AuthorityError> {
        let _guards = self.acquire_chain_guards(&[cid.to_string()]).await;
        const MAX_ATTEMPTS: usize = 8;
        for attempt in 0..MAX_ATTEMPTS {
            let transaction = self
                .db
                .begin_with_config(policy_isolation_level(&self.db), None)
                .await
                .map_err(|_| AuthorityError::TransactionFailed)?;
            let row = delegation_row(&transaction, cid, true).await?;
            let previous = status_from_model(&row)?;
            validate_status_transition(&previous, &status)?;
            let previous_checked_at = row.status_checked_at.clone();
            let previous_fresh_until = row.status_fresh_until.clone();
            let previous_sequence = row.status_sequence;
            let previous_revoked_at = row.revoked_at.clone();
            #[cfg(test)]
            if attempt == 0 {
                self.wait_at_race_barrier().await;
            }
            let mut update = policy_delegation::Entity::update_many()
                .col_expr(
                    policy_delegation::Column::StatusCheckedAt,
                    Expr::value(db_time(status.checked_at)?),
                )
                .col_expr(
                    policy_delegation::Column::StatusFreshUntil,
                    Expr::value(db_time(status.fresh_until)?),
                )
                .col_expr(
                    policy_delegation::Column::StatusSequence,
                    Expr::value(
                        i64::try_from(status.sequence)
                            .map_err(|_| AuthorityError::AuthorityStateUnavailable)?,
                    ),
                )
                .col_expr(
                    policy_delegation::Column::RevokedAt,
                    Expr::value(status.revoked_at.map(db_time).transpose()?),
                )
                .filter(policy_delegation::Column::DelegationCid.eq(cid))
                .filter(policy_delegation::Column::StatusSequence.eq(previous_sequence))
                .filter(policy_delegation::Column::StatusCheckedAt.eq(previous_checked_at))
                .filter(policy_delegation::Column::StatusFreshUntil.eq(previous_fresh_until));
            update = match previous_revoked_at {
                Some(revoked_at) => {
                    update.filter(policy_delegation::Column::RevokedAt.eq(revoked_at))
                }
                None => update.filter(policy_delegation::Column::RevokedAt.is_null()),
            };
            match update.exec(&transaction).await {
                Ok(updated) if updated.rows_affected == 1 => match transaction.commit().await {
                    Ok(()) => return Ok(()),
                    Err(error)
                        if attempt + 1 < MAX_ATTEMPTS && retryable_sqlite_conflict(&error) =>
                    {
                        sqlite_conflict_backoff(attempt).await;
                        continue;
                    }
                    Err(_) => return Err(AuthorityError::TransactionFailed),
                },
                Ok(_) => {
                    transaction
                        .rollback()
                        .await
                        .map_err(|_| AuthorityError::TransactionFailed)?;
                    if attempt + 1 < MAX_ATTEMPTS {
                        tokio::task::yield_now().await;
                        continue;
                    }
                    return Err(AuthorityError::AuthorityStateUnavailable);
                }
                Err(error) => {
                    transaction
                        .rollback()
                        .await
                        .map_err(|_| AuthorityError::TransactionFailed)?;
                    if attempt + 1 < MAX_ATTEMPTS && retryable_sqlite_conflict(&error) {
                        sqlite_conflict_backoff(attempt).await;
                        continue;
                    }
                    return Err(AuthorityError::TransactionFailed);
                }
            }
        }
        Err(AuthorityError::AuthorityStateUnavailable)
    }

    /// Apply an authenticated status observation while the composing caller's
    /// transaction is open. Equal observations are idempotent; rollback,
    /// stale observations, and resurrection after revocation are rejected.
    pub async fn apply_status_in_transaction(
        &self,
        transaction: &DatabaseTransaction,
        cid: &str,
        observation: &AuthorityStatusObservation,
        now: OffsetDateTime,
    ) -> Result<(), AuthorityError> {
        if observation.checked_at > now
            || observation.fresh_until <= now
            || now - observation.checked_at > time::Duration::seconds(MAX_STATUS_AGE_SECONDS)
            || observation.fresh_until - observation.checked_at
                > time::Duration::seconds(MAX_STATUS_AGE_SECONDS)
        {
            return Err(AuthorityError::AuthorityStateUnavailable);
        }
        let row = delegation_row(transaction, cid, true).await?;
        let previous = status_from_model(&row)?;
        let next = AuthorityStatus {
            checked_at: observation.checked_at,
            fresh_until: observation.fresh_until,
            sequence: observation.sequence,
            revoked_at: observation.revoked_at,
        };
        if next == previous {
            return Ok(());
        }
        validate_status_transition(&previous, &next)?;
        let updated = policy_delegation::Entity::update_many()
            .col_expr(
                policy_delegation::Column::StatusCheckedAt,
                Expr::value(db_time(next.checked_at)?),
            )
            .col_expr(
                policy_delegation::Column::StatusFreshUntil,
                Expr::value(db_time(next.fresh_until)?),
            )
            .col_expr(
                policy_delegation::Column::StatusSequence,
                Expr::value(
                    i64::try_from(next.sequence).map_err(|_| AuthorityError::SchemaInvalid)?,
                ),
            )
            .col_expr(
                policy_delegation::Column::RevokedAt,
                Expr::value(next.revoked_at.map(db_time).transpose()?),
            )
            .filter(policy_delegation::Column::DelegationCid.eq(cid))
            .filter(policy_delegation::Column::StatusSequence.eq(previous.sequence as i64))
            .filter(policy_delegation::Column::StatusCheckedAt.eq(row.status_checked_at))
            .filter(policy_delegation::Column::StatusFreshUntil.eq(row.status_fresh_until))
            .exec(transaction)
            .await
            .map_err(|_| AuthorityError::TransactionFailed)?;
        if updated.rows_affected != 1 {
            return Err(AuthorityError::AuthorityStateUnavailable);
        }
        Ok(())
    }

    async fn acquire_chain_guards(&self, cids: &[String]) -> Vec<tokio::sync::OwnedMutexGuard<()>> {
        let mut keys = cids.to_vec();
        keys.sort();
        keys.dedup();
        let locks = {
            let mut registry = self.chain_locks.lock().await;
            registry.retain(|_, lock| lock.strong_count() > 0);
            keys.into_iter()
                .map(|key| {
                    if let Some(lock) = registry.get(&key).and_then(Weak::upgrade) {
                        lock
                    } else {
                        let lock = Arc::new(tokio::sync::Mutex::new(()));
                        registry.insert(key, Arc::downgrade(&lock));
                        lock
                    }
                })
                .collect::<Vec<_>>()
        };
        let mut guards = Vec::with_capacity(locks.len());
        for lock in locks {
            guards.push(lock.lock_owned().await);
        }
        guards
    }

    pub async fn challenge(&self, id: &str) -> Result<ChallengeState, AuthorityError> {
        let row = policy_challenge::Entity::find_by_id(id.to_string())
            .one(&self.db)
            .await
            .map_err(|_| AuthorityError::ChallengeNotFound)?
            .ok_or(AuthorityError::ChallengeNotFound)?;
        challenge_from_model(row)
    }

    pub async fn artifact(&self, cid: &str) -> Result<PolicyDelegation, AuthorityError> {
        let row = policy_delegation::Entity::find_by_id(cid.to_string())
            .one(&self.db)
            .await
            .map_err(|_| AuthorityError::AuthorityStateUnavailable)?
            .ok_or(AuthorityError::AuthorityStateUnavailable)?;
        artifact_from_model(&row)
    }

    pub async fn artifact_in_transaction(
        &self,
        transaction: &DatabaseTransaction,
        cid: &str,
    ) -> Result<PolicyDelegation, AuthorityError> {
        let row = delegation_row(transaction, cid, true).await?;
        artifact_from_model(&row)
    }

    pub async fn edges(&self, cid: &str) -> Result<Vec<VerifiedEdge>, AuthorityError> {
        policy_edge::Entity::find()
            .filter(policy_edge::Column::ChildCid.eq(cid))
            .order_by_asc(policy_edge::Column::Position)
            .all(&self.db)
            .await
            .map_err(|_| AuthorityError::AuthorityStateUnavailable)?
            .into_iter()
            .map(edge_from_model)
            .collect()
    }

    pub async fn audit(&self, issuance_id: &str) -> Result<IssuanceAudit, AuthorityError> {
        let row = policy_issuance_audit::Entity::find_by_id(issuance_id.to_string())
            .one(&self.db)
            .await
            .map_err(|_| AuthorityError::AuthorityStateUnavailable)?
            .ok_or(AuthorityError::AuthorityStateUnavailable)?;
        serde_json::from_value(row.audit_json)
            .map_err(|_| AuthorityError::AuthorityStateUnavailable)
    }

    #[cfg(test)]
    pub(super) async fn status_for_test(
        &self,
        cid: &str,
    ) -> Result<AuthorityStatus, AuthorityError> {
        let row = delegation_row(&self.db, cid, false).await?;
        status_from_model(&row)
    }

    async fn ensure_live(
        &self,
        cid: &str,
        now: OffsetDateTime,
        ancestor: bool,
    ) -> Result<PolicyDelegation, AuthorityError> {
        self.ensure_live_on(&self.db, cid, now, ancestor, false)
            .await
    }

    async fn ensure_live_on<C: ConnectionTrait>(
        &self,
        connection: &C,
        cid: &str,
        now: OffsetDateTime,
        ancestor: bool,
        lock_exclusive: bool,
    ) -> Result<PolicyDelegation, AuthorityError> {
        let row = delegation_row(connection, cid, lock_exclusive).await?;
        ensure_live_model(&row, now, ancestor)
    }

    async fn ancestry_cids(&self, cid: &str) -> Result<Vec<String>, AuthorityError> {
        let mut stack = vec![(cid.to_string(), 0usize)];
        let mut visited = HashSet::new();
        while let Some((current, depth)) = stack.pop() {
            if depth > MAX_ANCESTRY_DEPTH || !visited.insert(current.clone()) {
                return Err(AuthorityError::AncestryTooDeep);
            }
            for edge in self.edges(&current).await? {
                stack.push((edge.parent_cid, depth + 1));
            }
        }
        Ok(visited.into_iter().collect())
    }

    pub async fn validate_for_invocation(
        &self,
        cid: &str,
        now: OffsetDateTime,
    ) -> Result<(), AuthorityError> {
        let mut stack = vec![(cid.to_string(), false, 0usize)];
        let mut visited = HashSet::new();
        while let Some((current, ancestor, depth)) = stack.pop() {
            if depth > MAX_ANCESTRY_DEPTH || !visited.insert(current.clone()) {
                return Err(AuthorityError::AncestryTooDeep);
            }
            let artifact = self.ensure_live(&current, now, ancestor).await?;
            let edges = self.edges(&current).await?;
            validate_persisted_edges(&artifact, &edges)?;
            stack.extend(
                edges
                    .into_iter()
                    .rev()
                    .map(|edge| (edge.parent_cid, true, depth + 1)),
            );
        }
        Ok(())
    }

    /// Revalidates the complete ancestry/revocation chain for `cid` with
    /// exclusive row locks held on the caller's transaction, so a composing
    /// service (such as the exact-email #117 bridge) can persist its own
    /// replay and session effects atomically with this authority check. This
    /// is the only supported way to compose #117 revalidation with another
    /// service's durable effects in one transaction.
    pub async fn validate_for_invocation_in_transaction(
        &self,
        transaction: &DatabaseTransaction,
        cid: &str,
        now: OffsetDateTime,
    ) -> Result<(), AuthorityError> {
        let mut stack = vec![(cid.to_owned(), false, 0usize)];
        let mut ancestry = HashMap::new();
        while let Some((current, ancestor, depth)) = stack.pop() {
            if depth > MAX_ANCESTRY_DEPTH || ancestry.contains_key(&current) {
                return Err(AuthorityError::AncestryTooDeep);
            }
            let row = delegation_row(transaction, &current, true).await?;
            let verified = ensure_live_model(&row, now, ancestor)?;
            let edges = edges_on(transaction, &current).await?;
            validate_persisted_edges(&verified, &edges)?;
            ancestry.insert(current.clone(), verified);
            stack.extend(
                edges
                    .into_iter()
                    .rev()
                    .map(|edge| (edge.parent_cid, true, depth + 1)),
            );
        }
        let mut locked_artifacts = HashMap::new();
        locked_artifacts.extend(ancestry);
        validate_locked_ancestry(transaction, cid, &locked_artifacts).await
    }

    async fn persist_root_atomic(
        &self,
        artifact: VerifiedDelegation,
        audit: IssuanceAudit,
        challenge_id: String,
        consumed_at: OffsetDateTime,
    ) -> Result<(), AuthorityError> {
        let transaction = self
            .db
            .begin_with_config(policy_isolation_level(&self.db), None)
            .await
            .map_err(|_| AuthorityError::TransactionFailed)?;
        let operation = self
            .persist_root_in_transaction(&transaction, artifact, audit, challenge_id, consumed_at)
            .await;
        match operation {
            Ok(()) => transaction
                .commit()
                .await
                .map_err(|_| AuthorityError::TransactionFailed),
            Err(error) => {
                transaction
                    .rollback()
                    .await
                    .map_err(|_| AuthorityError::TransactionFailed)?;
                Err(error)
            }
        }
    }

    /// Persist a verified root, its status/edges/audit, and consume its
    /// challenge on the caller's transaction. The caller owns the final
    /// commit so protocol JTI/handle effects can be atomic with #117.
    pub async fn persist_root_in_transaction(
        &self,
        transaction: &DatabaseTransaction,
        artifact: VerifiedDelegation,
        audit: IssuanceAudit,
        challenge_id: String,
        consumed_at: OffsetDateTime,
    ) -> Result<(), AuthorityError> {
        let mut authority_cids = artifact.0.proof_cids.clone();
        authority_cids.sort();
        authority_cids.dedup();
        if authority_cids.len() != 2 {
            return Err(AuthorityError::ProofSetUnmatched);
        }
        for cid in authority_cids {
            self.ensure_live_on(transaction, &cid, consumed_at, false, true)
                .await?;
        }
        #[cfg(test)]
        self.wait_at_race_barrier().await;
        let challenge = policy_challenge::Entity::find_by_id(challenge_id.clone())
            .one(transaction)
            .await
            .map_err(|_| AuthorityError::TransactionFailed)?
            .ok_or(AuthorityError::ChallengeNotFound)?;
        if challenge.consumed_at.is_some() {
            return Err(AuthorityError::ChallengeConsumed);
        }
        let challenge = challenge_from_model(challenge)?;
        if consumed_at < challenge.issued_at || consumed_at >= challenge.expires_at {
            return Err(AuthorityError::ChallengeExpired);
        }
        let consumed = policy_challenge::Entity::update_many()
            .col_expr(
                policy_challenge::Column::ConsumedAt,
                Expr::value(db_time(consumed_at)?),
            )
            .filter(policy_challenge::Column::ChallengeId.eq(challenge_id))
            .filter(policy_challenge::Column::ConsumedAt.is_null())
            .exec(transaction)
            .await
            .map_err(|_| AuthorityError::TransactionFailed)?;
        if consumed.rows_affected != 1 {
            return Err(AuthorityError::ChallengeConsumed);
        }

        let status = AuthorityStatus {
            checked_at: consumed_at,
            fresh_until: consumed_at + time::Duration::seconds(MAX_STATUS_AGE_SECONDS),
            sequence: 0,
            revoked_at: None,
        };
        policy_delegation::Entity::insert(artifact_model(&artifact, &status)?)
            .exec(transaction)
            .await
            .map_err(|_| AuthorityError::TransactionFailed)?;
        policy_issuance_audit::ActiveModel {
            issuance_id: Set(audit.issuance_id.clone()),
            session_delegation_cid: Set(audit.session_delegation_cid.clone()),
            audit_json: Set(
                serde_json::to_value(&audit).map_err(|_| AuthorityError::TransactionFailed)?
            ),
        }
        .insert(transaction)
        .await
        .map_err(|_| AuthorityError::TransactionFailed)?;
        for (position, parent_cid) in artifact.0.proof_cids.iter().enumerate() {
            policy_edge::ActiveModel {
                child_cid: Set(artifact.0.delegation_cid.clone()),
                position: Set(position as i32),
                parent_cid: Set(parent_cid.clone()),
                edge_kind: Set("authority".to_string()),
            }
            .insert(transaction)
            .await
            .map_err(|_| AuthorityError::TransactionFailed)?;
        }
        Ok(())
    }

    async fn persist_descendant_atomic(
        &self,
        artifact: VerifiedDelegation,
        verified_at: OffsetDateTime,
        mut ancestry: Vec<String>,
    ) -> Result<(), AuthorityError> {
        let transaction = self
            .db
            .begin_with_config(policy_isolation_level(&self.db), None)
            .await
            .map_err(|_| AuthorityError::TransactionFailed)?;
        let operation = async {
            ancestry.sort();
            ancestry.dedup();
            let parent_cid = &artifact.0.proof_cids[0];
            let mut locked_artifacts = HashMap::new();
            for cid in &ancestry {
                let row = delegation_row(&transaction, cid, true).await?;
                let verified = ensure_live_model(&row, verified_at, cid != parent_cid)?;
                locked_artifacts.insert(cid.clone(), verified);
            }
            validate_locked_ancestry(&transaction, parent_cid, &locked_artifacts).await?;
            #[cfg(test)]
            self.wait_at_race_barrier().await;
            policy_delegation::Entity::insert(artifact_model(
                &artifact,
                &AuthorityStatus {
                    checked_at: verified_at,
                    fresh_until: verified_at + time::Duration::seconds(MAX_STATUS_AGE_SECONDS),
                    sequence: 0,
                    revoked_at: None,
                },
            )?)
            .exec(&transaction)
            .await
            .map_err(|_| AuthorityError::TransactionFailed)?;
            policy_edge::ActiveModel {
                child_cid: Set(artifact.0.delegation_cid.clone()),
                position: Set(0),
                parent_cid: Set(artifact.0.proof_cids[0].clone()),
                edge_kind: Set("immediate".to_string()),
            }
            .insert(&transaction)
            .await
            .map_err(|_| AuthorityError::TransactionFailed)?;
            Ok(())
        }
        .await;
        match operation {
            Ok(()) => transaction
                .commit()
                .await
                .map_err(|_| AuthorityError::TransactionFailed),
            Err(error) => {
                transaction
                    .rollback()
                    .await
                    .map_err(|_| AuthorityError::TransactionFailed)?;
                Err(error)
            }
        }
    }
}

pub struct DatabaseAuthorityKernel {
    store: DatabaseAuthorityStore,
    running_node_did: String,
}

impl DatabaseAuthorityKernel {
    pub fn new(store: DatabaseAuthorityStore, running_node_did: impl Into<String>) -> Self {
        Self {
            store,
            running_node_did: running_node_did.into(),
        }
    }

    /// Validate and persist a verified root on an existing transaction. This
    /// is the transaction boundary used by a composing protocol: root,
    /// status, ordered authority edges, issuance audit, and challenge
    /// consumption are committed by the caller together with its JTI/handle
    /// records.
    #[allow(clippy::too_many_arguments)]
    pub async fn issue_root_in_transaction(
        &self,
        transaction: &DatabaseTransaction,
        policy_authority: &VerifiedDelegation,
        policy_enforcement: &VerifiedDelegation,
        policy_state: &VerifiedPolicyState,
        root: VerifiedDelegation,
        binding: &VerifiedAttestedEnforcerBinding,
        decision: &TrustedPolicyDecision,
        bindings: &IssuanceBindings,
    ) -> Result<(), AuthorityError> {
        validate_authority_pair(
            &policy_authority.0,
            &policy_enforcement.0,
            policy_state,
            &self.running_node_did,
        )?;
        self.store
            .validate_for_invocation_in_transaction(
                transaction,
                &policy_authority.0.delegation_cid,
                bindings.now,
            )
            .await?;
        self.store
            .validate_for_invocation_in_transaction(
                transaction,
                &policy_enforcement.0.delegation_cid,
                bindings.now,
            )
            .await?;
        let challenge = policy_challenge::Entity::find_by_id(bindings.challenge_id.clone())
            .one(transaction)
            .await
            .map_err(|_| AuthorityError::TransactionFailed)?
            .ok_or(AuthorityError::ChallengeNotFound)?;
        let challenge = challenge_from_model(challenge)?;
        if challenge.consumed_at.is_some() {
            return Err(AuthorityError::ChallengeConsumed);
        }
        let audit = validate_root(
            &policy_authority.0,
            &policy_enforcement.0,
            policy_state,
            &challenge,
            &root.0,
            binding,
            decision,
            bindings,
            &self.running_node_did,
        )?;
        self.store
            .persist_root_in_transaction(
                transaction,
                root,
                audit,
                bindings.challenge_id.clone(),
                bindings.now,
            )
            .await
    }

    /// Sign a node root with configured key material, re-verify its signature
    /// and CID, then issue it on the caller's transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_and_issue_root_in_transaction(
        &self,
        transaction: &DatabaseTransaction,
        policy_authority: &VerifiedDelegation,
        policy_enforcement: &VerifiedDelegation,
        policy_state: &VerifiedPolicyState,
        root: PolicyDelegation,
        signer: &dyn NodeRootSigner,
        binding: &VerifiedAttestedEnforcerBinding,
        decision: &TrustedPolicyDecision,
        bindings: &IssuanceBindings,
    ) -> Result<(), AuthorityError> {
        let verified = AuthorityArtifactVerifier.sign_and_verify_root(root, signer)?;
        self.issue_root_in_transaction(
            transaction,
            policy_authority,
            policy_enforcement,
            policy_state,
            verified,
            binding,
            decision,
            bindings,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn issue_root(
        &self,
        policy_authority: &VerifiedDelegation,
        policy_enforcement: &VerifiedDelegation,
        policy_state: &VerifiedPolicyState,
        root: VerifiedDelegation,
        binding: &VerifiedAttestedEnforcerBinding,
        decision: &TrustedPolicyDecision,
        bindings: &IssuanceBindings,
    ) -> Result<(), AuthorityError> {
        validate_authority_pair(
            &policy_authority.0,
            &policy_enforcement.0,
            policy_state,
            &self.running_node_did,
        )?;
        let _guards = self
            .store
            .acquire_chain_guards(&[
                policy_authority.0.delegation_cid.clone(),
                policy_enforcement.0.delegation_cid.clone(),
            ])
            .await;
        self.store
            .validate_for_invocation(&policy_authority.0.delegation_cid, bindings.now)
            .await?;
        self.store
            .validate_for_invocation(&policy_enforcement.0.delegation_cid, bindings.now)
            .await?;
        let challenge = self.store.challenge(&bindings.challenge_id).await?;
        if challenge.consumed_at.is_some() {
            return Err(AuthorityError::ChallengeConsumed);
        }
        let audit = validate_root(
            &policy_authority.0,
            &policy_enforcement.0,
            policy_state,
            &challenge,
            &root.0,
            binding,
            decision,
            bindings,
            &self.running_node_did,
        )?;
        self.store
            .persist_root_atomic(root, audit, bindings.challenge_id.clone(), bindings.now)
            .await
    }

    pub async fn persist_descendant(
        &self,
        descendant: VerifiedDelegation,
        now: OffsetDateTime,
    ) -> Result<(), AuthorityError> {
        let parent_cid = descendant
            .0
            .proof_cids
            .first()
            .ok_or(AuthorityError::DescendantParentMismatch)?;
        let ancestry = self.store.ancestry_cids(parent_cid).await?;
        let _guards = self.store.acquire_chain_guards(&ancestry).await;
        let parent = self.store.artifact(parent_cid).await?;
        if parent.delegation_mode == DelegationMode::ConditionalMint {
            return Err(AuthorityError::ConditionalMintNotParent);
        }
        let root_cid = if parent.role == DelegationRole::PolicySessionRoot {
            parent.delegation_cid.as_str()
        } else {
            parent.fact("rootSessionDelegationCid")?
        };
        let root = self.store.artifact(root_cid).await?;
        validate_descendant(&descendant.0, &parent, &root)?;
        self.store
            .validate_for_invocation(&parent.delegation_cid, now)
            .await?;
        self.store
            .persist_descendant_atomic(descendant, now, ancestry)
            .await
    }

    pub async fn validate_for_invocation(
        &self,
        cid: &str,
        now: OffsetDateTime,
    ) -> Result<(), AuthorityError> {
        self.store.validate_for_invocation(cid, now).await
    }
}

fn validate_persisted_edges(
    artifact: &PolicyDelegation,
    edges: &[VerifiedEdge],
) -> Result<(), AuthorityError> {
    match artifact.role {
        DelegationRole::PolicySessionRoot => {
            if edges.len() != 2
                || edges[0].kind != EdgeKind::Authority
                || edges[0].position != 0
                || edges[1].kind != EdgeKind::Authority
                || edges[1].position != 1
                || edges[0].parent_cid != artifact.proof_cids[0]
                || edges[1].parent_cid != artifact.proof_cids[1]
            {
                return Err(AuthorityError::AuthorityStateUnavailable);
            }
        }
        DelegationRole::PolicySessionDescendant => {
            if edges.len() != 1
                || edges[0].kind != EdgeKind::Immediate
                || edges[0].position != 0
                || edges[0].parent_cid != artifact.proof_cids[0]
            {
                return Err(AuthorityError::AuthorityStateUnavailable);
            }
        }
        _ if !edges.is_empty() => return Err(AuthorityError::AuthorityStateUnavailable),
        _ => {}
    }
    Ok(())
}

async fn delegation_row<C: ConnectionTrait>(
    connection: &C,
    cid: &str,
    lock_exclusive: bool,
) -> Result<policy_delegation::Model, AuthorityError> {
    let query = policy_delegation::Entity::find_by_id(cid.to_string());
    let query = match (lock_exclusive, connection.get_database_backend()) {
        (true, DbBackend::Postgres | DbBackend::MySql) => query.lock_exclusive(),
        _ => query,
    };
    query
        .one(connection)
        .await
        .map_err(|_| AuthorityError::AuthorityStateUnavailable)?
        .ok_or(AuthorityError::AuthorityStateUnavailable)
}

async fn edges_on<C: ConnectionTrait>(
    connection: &C,
    cid: &str,
) -> Result<Vec<VerifiedEdge>, AuthorityError> {
    policy_edge::Entity::find()
        .filter(policy_edge::Column::ChildCid.eq(cid))
        .order_by_asc(policy_edge::Column::Position)
        .all(connection)
        .await
        .map_err(|_| AuthorityError::AuthorityStateUnavailable)?
        .into_iter()
        .map(edge_from_model)
        .collect()
}

async fn validate_locked_ancestry<C: ConnectionTrait>(
    connection: &C,
    start_cid: &str,
    locked_artifacts: &HashMap<String, PolicyDelegation>,
) -> Result<(), AuthorityError> {
    let mut stack = vec![(start_cid.to_string(), 0usize)];
    let mut visited = HashSet::new();
    while let Some((cid, depth)) = stack.pop() {
        if depth > MAX_ANCESTRY_DEPTH || !visited.insert(cid.clone()) {
            return Err(AuthorityError::AncestryTooDeep);
        }
        let artifact = locked_artifacts
            .get(&cid)
            .ok_or(AuthorityError::AuthorityStateUnavailable)?;
        let edges = edges_on(connection, &cid).await?;
        validate_persisted_edges(artifact, &edges)?;
        for edge in edges.into_iter().rev() {
            if !locked_artifacts.contains_key(&edge.parent_cid) {
                return Err(AuthorityError::AuthorityStateUnavailable);
            }
            stack.push((edge.parent_cid, depth + 1));
        }
    }
    if visited.len() != locked_artifacts.len() {
        return Err(AuthorityError::AuthorityStateUnavailable);
    }
    Ok(())
}

fn ensure_live_model(
    row: &policy_delegation::Model,
    now: OffsetDateTime,
    ancestor: bool,
) -> Result<PolicyDelegation, AuthorityError> {
    let artifact = artifact_from_model(row)?;
    if now < artifact.not_before()? || now >= artifact.expires_at()? {
        return Err(AuthorityError::SessionTimeInvalid);
    }
    let status = status_from_model(row)?;
    if status.checked_at > now
        || now - status.checked_at > time::Duration::seconds(MAX_STATUS_AGE_SECONDS)
        || status.fresh_until <= now
        || status.fresh_until - status.checked_at > time::Duration::seconds(MAX_STATUS_AGE_SECONDS)
    {
        return Err(AuthorityError::AuthorityStateUnavailable);
    }
    if status
        .revoked_at
        .is_some_and(|revoked_at| revoked_at <= now)
    {
        return Err(if ancestor {
            AuthorityError::DelegationAncestorRevoked
        } else {
            AuthorityError::DelegationRevoked
        });
    }
    Ok(artifact)
}

fn policy_isolation_level(connection: &DatabaseConnection) -> Option<sea_orm::IsolationLevel> {
    match connection.get_database_backend() {
        DbBackend::Postgres | DbBackend::MySql => Some(sea_orm::IsolationLevel::ReadCommitted),
        DbBackend::Sqlite => None,
    }
}

fn retryable_sqlite_conflict(error: &sea_orm::DbErr) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("database is locked") || message.contains("database is busy")
}

async fn sqlite_conflict_backoff(attempt: usize) {
    tokio::time::sleep(std::time::Duration::from_millis(
        5 * u64::try_from(attempt + 1).unwrap_or(1),
    ))
    .await;
}

fn artifact_model(
    artifact: &VerifiedDelegation,
    status: &AuthorityStatus,
) -> Result<policy_delegation::ActiveModel, AuthorityError> {
    Ok(policy_delegation::ActiveModel {
        delegation_cid: Set(artifact.0.delegation_cid.clone()),
        role: Set(enum_wire(artifact.0.role)?),
        delegation_mode: Set(enum_wire(artifact.0.delegation_mode)?),
        artifact_json: Set(
            serde_json::to_value(&artifact.0).map_err(|_| AuthorityError::SchemaInvalid)?
        ),
        not_before: Set(artifact.0.not_before.clone()),
        expires_at: Set(artifact.0.expires_at.clone()),
        status_checked_at: Set(db_time(status.checked_at)?),
        status_fresh_until: Set(Some(db_time(status.fresh_until)?)),
        status_sequence: Set(
            i64::try_from(status.sequence).map_err(|_| AuthorityError::SchemaInvalid)?
        ),
        revoked_at: Set(status.revoked_at.map(db_time).transpose()?),
    })
}

fn artifact_from_model(
    model: &policy_delegation::Model,
) -> Result<PolicyDelegation, AuthorityError> {
    let artifact: PolicyDelegation = serde_json::from_value(model.artifact_json.clone())
        .map_err(|_| AuthorityError::AuthorityStateUnavailable)?;
    artifact.validate_wire_shape()?;
    if artifact.delegation_cid != model.delegation_cid
        || enum_wire(artifact.role)? != model.role
        || enum_wire(artifact.delegation_mode)? != model.delegation_mode
        || artifact.not_before != model.not_before
        || artifact.expires_at != model.expires_at
    {
        return Err(AuthorityError::AuthorityStateUnavailable);
    }
    Ok(artifact)
}

fn challenge_from_model(model: policy_challenge::Model) -> Result<ChallengeState, AuthorityError> {
    let stored: StoredChallenge = serde_json::from_value(model.challenge_json)
        .map_err(|_| AuthorityError::AuthorityStateUnavailable)?;
    let mut challenge = ChallengeState::try_from(stored)?;
    if challenge.challenge_id != model.challenge_id
        || challenge.nonce_hash_hex != model.nonce_hash_hex
        || db_time(challenge.issued_at)? != model.issued_at
        || db_time(challenge.expires_at)? != model.expires_at
    {
        return Err(AuthorityError::AuthorityStateUnavailable);
    }
    challenge.consumed_at = model
        .consumed_at
        .as_deref()
        .map(db_time_parse)
        .transpose()?;
    validate_challenge_lifetime_for_read(&challenge)?;
    Ok(challenge)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StoredChallenge {
    challenge_id: String,
    nonce_hash_hex: String,
    owner_did: String,
    policy_id: String,
    policy_digest_hex: String,
    policy_delegation_cid: String,
    enforcement_delegation_cid: String,
    enforcer_did: String,
    node_audience: String,
    claimant_did: String,
    requested_capabilities_hash_hex: String,
    issued_at: String,
    expires_at: String,
}

impl TryFrom<&ChallengeState> for StoredChallenge {
    type Error = AuthorityError;

    fn try_from(challenge: &ChallengeState) -> Result<Self, Self::Error> {
        Ok(Self {
            challenge_id: challenge.challenge_id.clone(),
            nonce_hash_hex: challenge.nonce_hash_hex.clone(),
            owner_did: challenge.owner_did.clone(),
            policy_id: challenge.policy_id.clone(),
            policy_digest_hex: challenge.policy_digest_hex.clone(),
            policy_delegation_cid: challenge.policy_delegation_cid.clone(),
            enforcement_delegation_cid: challenge.enforcement_delegation_cid.clone(),
            enforcer_did: challenge.enforcer_did.clone(),
            node_audience: challenge.node_audience.clone(),
            claimant_did: challenge.claimant_did.clone(),
            requested_capabilities_hash_hex: challenge.requested_capabilities_hash_hex.clone(),
            issued_at: db_time(challenge.issued_at)?,
            expires_at: db_time(challenge.expires_at)?,
        })
    }
}

impl TryFrom<StoredChallenge> for ChallengeState {
    type Error = AuthorityError;

    fn try_from(challenge: StoredChallenge) -> Result<Self, Self::Error> {
        Ok(Self {
            challenge_id: challenge.challenge_id,
            nonce_hash_hex: challenge.nonce_hash_hex,
            owner_did: challenge.owner_did,
            policy_id: challenge.policy_id,
            policy_digest_hex: challenge.policy_digest_hex,
            policy_delegation_cid: challenge.policy_delegation_cid,
            enforcement_delegation_cid: challenge.enforcement_delegation_cid,
            enforcer_did: challenge.enforcer_did,
            node_audience: challenge.node_audience,
            claimant_did: challenge.claimant_did,
            requested_capabilities_hash_hex: challenge.requested_capabilities_hash_hex,
            issued_at: db_time_parse(&challenge.issued_at)?,
            expires_at: db_time_parse(&challenge.expires_at)?,
            consumed_at: None,
        })
    }
}

fn status_from_model(model: &policy_delegation::Model) -> Result<AuthorityStatus, AuthorityError> {
    let checked_at = db_time_parse(&model.status_checked_at)?;
    let status = AuthorityStatus {
        checked_at,
        fresh_until: model
            .status_fresh_until
            .as_deref()
            .map(db_time_parse)
            .transpose()?
            .unwrap_or(checked_at + time::Duration::seconds(MAX_STATUS_AGE_SECONDS)),
        sequence: u64::try_from(model.status_sequence)
            .map_err(|_| AuthorityError::AuthorityStateUnavailable)?,
        revoked_at: model.revoked_at.as_deref().map(db_time_parse).transpose()?,
    };
    if status.fresh_until <= status.checked_at
        || status.fresh_until - status.checked_at > time::Duration::seconds(MAX_STATUS_AGE_SECONDS)
    {
        return Err(AuthorityError::AuthorityStateUnavailable);
    }
    if status
        .revoked_at
        .is_some_and(|revoked_at| revoked_at > status.checked_at)
    {
        return Err(AuthorityError::AuthorityStateUnavailable);
    }
    Ok(status)
}

fn edge_from_model(model: policy_edge::Model) -> Result<VerifiedEdge, AuthorityError> {
    Ok(VerifiedEdge {
        child_cid: model.child_cid,
        parent_cid: model.parent_cid,
        kind: match model.edge_kind.as_str() {
            "authority" => EdgeKind::Authority,
            "immediate" => EdgeKind::Immediate,
            _ => return Err(AuthorityError::AuthorityStateUnavailable),
        },
        position: u8::try_from(model.position)
            .map_err(|_| AuthorityError::AuthorityStateUnavailable)?,
    })
}

fn enum_wire<T: Serialize>(value: T) -> Result<String, AuthorityError> {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .ok_or(AuthorityError::SchemaInvalid)
}

fn db_time(value: OffsetDateTime) -> Result<String, AuthorityError> {
    value
        .format(&Rfc3339)
        .map_err(|_| AuthorityError::TimestampNoncanonical)
}

fn db_time_parse(value: &str) -> Result<OffsetDateTime, AuthorityError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AuthorityError::AuthorityStateUnavailable)
}
