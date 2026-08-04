//! TC-405 unified addressed-share control plane.
//!
//! The data plane deliberately remains the ordinary TinyCloud delegation
//! graph.  This module owns only the extra evidence needed to admit a
//! policy-session UCAN: the sibling-root registration, signed status, the
//! challenge/claim replay boundary, and the first-admission gate.

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use rand::RngCore;
use rocket::{http::Status, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
use tinycloud_auth::authorization::TinyCloudDelegation;
use tinycloud_auth::multihash_codetable::MultihashDigest;
use tinycloud_auth::share_email_evidence::{verify_detached_ed25519, IssuerKey};
use tinycloud_auth::ssi::{
    dids::{AnyDidMethod, DIDBuf},
    jwk::{Algorithm, Base64urlUInt, OctetParams, Params, JWK},
};
use tinycloud_auth::{
    identity::{did_principal_matches, parse_pkh_did},
    resource::{ResourceId, SpaceId},
};
use tinycloud_core::{
    events::{Delegation, SerializedEvent},
    hash::hash,
    keys::StaticSecret,
    models::{
        abilities, delegation as delegation_model, policy_v3_challenge, policy_v3_registration,
        policy_v3_root, policy_v3_session, revocation, space,
    },
    relationships::parent_delegations,
    sea_orm::{
        sea_query::Expr, ActiveModelTrait, ColumnTrait, DatabaseConnection, DatabaseTransaction,
        EntityTrait, QueryFilter, QuerySelect, Set, TransactionTrait,
    },
    types::SpaceIdWrap,
    util::{DelegationInfo, InvocationInfo},
};

pub const POLICY_SESSION_PROFILE: &str = "policy-session-ucan/v1";
pub const POLICY_V1_SCHEMA: &str = "xyz.tinycloud.policy/policy/v1";
pub const POLICY_V2_SCHEMA: &str = "xyz.tinycloud.policy/policy/v2";
pub const POLICY_CREDENTIAL_REQUIREMENT_V1: &str = "TinyCloudPolicyCredentialRequirement";
pub const CREDENTIAL_PRESENTATION_V3_SCHEMA: &str = "xyz.tinycloud.policy/presentation/v3";
const CREDENTIAL_PRESENTATION_V3_DOMAIN: &[u8] = b"xyz.tinycloud.policy/Presentation/v3\0";
pub const POLICY_ENFORCEMENT_V2_SCHEMA: &str = "xyz.tinycloud.policy/enforcement-delegation/v2";
pub const ATTESTED_ENFORCER_V2_SCHEMA: &str = "xyz.tinycloud.policy/attested-enforcer/v2";
pub const ROOT_STATUS_V1_SCHEMA: &str = "xyz.tinycloud.policy/root-status/v1";
pub const ROOT_REVOCATION_V1_SCHEMA: &str = "xyz.tinycloud.policy/root-revocation/v1";
pub const LAST_V2_CREATE_AT: &str = "2026-09-30T00:00:00Z";
pub const MAX_LEGACY_ENVELOPE_EXPIRES_AT: &str = "2026-12-29T00:00:00Z";
pub const LAST_V2_READ_AT: &str = "2027-01-05T00:00:00Z";

const STATUS_DOMAIN: &[u8] = b"xyz.tinycloud.policy/RootStatusCheckpoint/v1\0";
const CONTENT_SOURCE_DOMAIN: &[u8] = b"xyz.tinycloud.policy/ContentSource/v1\0";
const CAPABILITY_CEILING_DOMAIN: &[u8] = b"xyz.tinycloud.policy/PolicyCapability/v1\0";
const NATIVE_PROJECTION_DOMAIN: &[u8] = b"xyz.tinycloud.policy/NativeProjection/v1\0";
const MAX_STATUS_AGE_SECONDS: i64 = 300;
const MAX_SESSION_TTL_SECONDS: i64 = 60;

#[derive(Clone)]
pub struct PolicyV3Runtime {
    pub conn: DatabaseConnection,
    pub node_did: String,
    signer: StaticSecret,
    credential_issuer: Option<IssuerKey>,
    sqlite_writer_lock: Option<Arc<tokio::sync::Mutex<()>>>,
}

impl PolicyV3Runtime {
    pub fn new(
        conn: DatabaseConnection,
        node_did: impl Into<String>,
        signer: StaticSecret,
    ) -> Self {
        Self {
            conn,
            node_did: node_did.into(),
            signer,
            credential_issuer: None,
            sqlite_writer_lock: None,
        }
    }

    pub fn with_sqlite_writer_lock(mut self, lock: Option<Arc<tokio::sync::Mutex<()>>>) -> Self {
        self.sqlite_writer_lock = lock;
        self
    }

    /// Install the operator-authenticated OpenCredentials issuer tuple used
    /// by policy/v2 admission. Policy/v1 remains available without it.
    pub fn with_credential_issuer(mut self, issuer: IssuerKey) -> Self {
        self.credential_issuer = Some(issuer);
        self
    }

    async fn is_registered_policy_root(&self, cid: &str) -> Result<bool, &'static str> {
        policy_v3_root::Entity::find_by_id(cid.to_owned())
            .one(&self.conn)
            .await
            .map(|root| root.is_some())
            .map_err(|_| "policy-root-unavailable")
    }

    pub async fn first_admission_allowed(&self, event: &Delegation) -> Result<(), &'static str> {
        if !is_policy_session(&event.0) {
            return Ok(());
        }
        let Ok(encoded) = std::str::from_utf8(event.serialized_bytes()) else {
            return Err("policy-session-bytes-invalid");
        };
        let Ok(reparsed) = decode_delegation(encoded) else {
            return Err("policy-session-decode-invalid");
        };
        if reparsed.serialized_bytes() != event.serialized_bytes()
            || reparsed.content_hash() != event.content_hash()
            || !is_policy_session(&reparsed.0)
            || reparsed.0.parents.len() != 2
        {
            return Err("policy-session-roundtrip-invalid");
        }
        let policy_cid = fact(&event.0.delegation, "policyCid").unwrap_or_default();
        let Some(registration) = policy_v3_registration::Entity::find_by_id(policy_cid)
            .one(&self.conn)
            .await
            .ok()
            .flatten()
        else {
            return Err("policy-session-registration-missing");
        };
        let proofs: Vec<String> = event.0.parents.iter().map(ToString::to_string).collect();
        if proofs
            != [
                registration.policy_root_cid.clone(),
                registration.enforcement_root_cid.clone(),
            ]
        {
            return Err("policy-session-proof-order-invalid");
        }
        let Ok(enforcer_did) = self
            .authenticated_registration_enforcer(&registration, OffsetDateTime::now_utc())
            .await
        else {
            return Err("policy-session-enforcer-invalid");
        };
        if fact(&event.0.delegation, "recipientDid") != Some(event.0.delegate.as_str())
            || fact(&event.0.delegation, "enforcerDid") != Some(enforcer_did.as_str())
            || fact(&event.0.delegation, "nodeAudience") != Some(self.node_did.as_str())
        {
            return Err("policy-session-facts-invalid");
        }
        let session_cid = event.content_hash().to_cid(0x55).to_string();
        let Some(session) = policy_v3_session::Entity::find_by_id(session_cid.clone())
            .one(&self.conn)
            .await
            .ok()
            .flatten()
        else {
            return Err("policy-session-admission-missing");
        };
        if session.state != "admitted"
            || session.session_cid != session_cid
            || session.authorization_bytes != event.serialized_bytes()
            || session.recipient_did != event.0.delegate
        {
            return Err("policy-session-admission-mismatch");
        }
        for cid in [
            &registration.policy_root_cid,
            &registration.enforcement_root_cid,
        ] {
            let Some(root) = policy_v3_root::Entity::find_by_id(cid.clone())
                .one(&self.conn)
                .await
                .ok()
                .flatten()
            else {
                return Err("policy-session-root-missing");
            };
            if validate_persisted_root(&root, cid, &registration.policy_cid, &self.node_did)
                .await
                .is_err()
                || validate_stored_root_status(
                    &root,
                    cid,
                    &self.node_did,
                    OffsetDateTime::now_utc(),
                    true,
                )
                .is_err()
            {
                return Err("policy-session-root-status-invalid");
            }
            let Some(graph_root) =
                delegation_model::Entity::find_by_id(tinycloud_core::hash::Hash::from(
                    match tinycloud_auth::ipld_core::cid::Cid::try_from(cid.as_str()) {
                        Ok(cid) => cid,
                        Err(_) => return Err("policy-session-root-cid-invalid"),
                    },
                ))
                .one(&self.conn)
                .await
                .ok()
                .flatten()
            else {
                return Err("policy-session-root-graph-missing");
            };
            if graph_root.serialization != root.authorization_bytes {
                return Err("policy-session-root-graph-mismatch");
            }
        }
        Ok(())
    }

    /// Public `/delegate` is an ordinary import surface.  Policy roots are
    /// control-plane evidence and may only enter the ordinary graph through
    /// registration; the first S0 enters it through the verified mint
    /// transition.  This closes the one-root child path without changing
    /// ordinary delegation admission.
    pub async fn ordinary_admission_allowed(
        &self,
        tinycloud: &crate::TinyCloud,
        event: &Delegation,
    ) -> Result<(), &'static str> {
        if is_policy_session(&event.0) {
            if event.0.parents.len() == 2 {
                return self.first_admission_allowed(event).await;
            }
            // A descendant carries the same protected profile fact and one
            // immediate parent. It is ordinary graph data, but it may enter
            // only below an already admitted S0; roots can never be used as
            // a one-parent substitute for the conjunctive mint.
            if event.0.parents.len() != 1 {
                return Err("policy-session-parent-count-invalid");
            }
            let Ok((_, parent)) = self
                .validate_policy_chain(tinycloud, event.0.parents[0])
                .await
            else {
                return Err("policy-session-parent-invalid");
            };
            return (event.0.delegator == parent.0.delegate
                && descendant_time_is_narrower(&event.0, &parent.0)
                && descendant_profile_is_inherited(&event.0, &parent.0)
                && capabilities_are_contained(&event.0.capabilities, &parent.0.capabilities)
                && verify_signed_delegation(&event.0.delegation).await.is_ok())
            .then_some(())
            .ok_or("policy-session-descendant-invalid");
        }
        if event.0.parents.is_empty() && is_policy_root(&event.0.delegation) {
            return Err("policy-root-requires-registration");
        }
        for parent in &event.0.parents {
            // The same persisted-root predicate guards both ordinary
            // delegation import and invocation fallback. A database error is
            // fail-closed because it is not safe to classify the parent as
            // ordinary graph authority when root registration is unknown.
            if self
                .is_registered_policy_root(&parent.to_string())
                .await
                .unwrap_or(true)
            {
                return Err("policy-root-cannot-be-ordinary-parent");
            }
        }
        Ok(())
    }

    pub async fn authorize_invocation(
        &self,
        tinycloud: &crate::TinyCloud,
        invocation: &InvocationInfo,
        now: OffsetDateTime,
    ) -> Result<bool, &'static str> {
        if invocation.parents.len() != 1 {
            for parent in invocation.parents.iter().copied() {
                if tinycloud
                    .load_signed_delegation(parent)
                    .await
                    .ok()
                    .flatten()
                    .is_some_and(|(_, event)| is_policy_session(&event.0))
                {
                    return Err("policy-session-requires-one-immediate-parent");
                }
            }
            return Ok(false);
        }
        let parent_cid = invocation.parents[0];
        let loaded = tinycloud.load_signed_delegation(parent_cid).await;
        let Some((immediate_row, immediate)) = (match loaded {
            Ok(parent) => parent,
            Err(_) if self.is_policy_protected_parent(parent_cid).await? => {
                return Err("policy-session-invalid");
            }
            Err(_) => return Ok(false),
        }) else {
            return Ok(false);
        };
        // Sibling roots are stored in the ordinary graph only so S0 can have
        // normal proof edges. Neither root is invocation authority by itself.
        // Reject before ordinary fallback: D_enforce's audience is the node,
        // so an enforcer-signed invocation would otherwise collapse AND.
        if self
            .is_registered_policy_root(&invocation.parents[0].to_string())
            .await?
        {
            return Err("policy-root-cannot-authorize-invocation");
        }
        if !is_policy_session(&immediate.0) {
            return Ok(false);
        }
        if immediate_row.delegatee != invocation.invoker
            || immediate.0.delegate != invocation.invoker
        {
            // Principal/audience mismatch is an ordinary graph authorization
            // failure. Defer it to the existing authorization path so TC-405
            // does not change its status contract or error vocabulary.
            return Ok(false);
        }
        if !capabilities_are_contained(&invocation.capabilities, &immediate.0.capabilities) {
            return Err("policy-invocation-capability-widening");
        }
        let (row, session) = self
            .validate_policy_chain(tinycloud, invocation.parents[0])
            .await?;
        let payload = invocation.invocation.payload();
        let invocation_expiry =
            OffsetDateTime::from_unix_timestamp(payload.expiration.as_seconds() as i64)
                .map_err(|_| "policy-invocation-time-invalid")?;
        let invocation_not_before = payload
            .not_before
            .and_then(|value| OffsetDateTime::from_unix_timestamp(value.as_seconds() as i64).ok())
            .ok_or("policy-invocation-not-before-missing")?;
        if invocation_expiry - invocation_not_before > Duration::seconds(60) {
            return Err("policy-invocation-lifetime-too-long");
        }
        let expires = session.0.expiry.ok_or("policy-session-invalid")?;
        let not_before = session.0.not_before.ok_or("policy-session-invalid")?;
        if now < not_before
            || now >= expires
            || expires - not_before > Duration::seconds(MAX_SESSION_TTL_SECONDS)
        {
            return Err("policy-session-expired");
        }
        let registration = policy_v3_registration::Entity::find_by_id(row.policy_cid.clone())
            .one(&self.conn)
            .await
            .map_err(|_| "policy-registration-unavailable")?
            .ok_or("policy-registration-missing")?;
        let proof_cids: Vec<String> = session.0.parents.iter().map(ToString::to_string).collect();
        if proof_cids
            != [
                registration.policy_root_cid.clone(),
                registration.enforcement_root_cid.clone(),
            ]
            || fact(&session.0.delegation, "policyCid") != Some(registration.policy_cid.as_str())
            || fact(&session.0.delegation, "policyDelegationCid")
                != Some(registration.policy_root_cid.as_str())
            || fact(&session.0.delegation, "enforcementDelegationCid")
                != Some(registration.enforcement_root_cid.as_str())
        {
            return Err("policy-session-proof-index-mismatch");
        }
        let policy_root = policy_v3_root::Entity::find_by_id(registration.policy_root_cid.clone())
            .one(&self.conn)
            .await
            .map_err(|_| "policy-root-unavailable")?
            .ok_or("policy-root-missing")?;
        let enforcement_root =
            policy_v3_root::Entity::find_by_id(registration.enforcement_root_cid.clone())
                .one(&self.conn)
                .await
                .map_err(|_| "enforcement-root-unavailable")?
                .ok_or("enforcement-root-missing")?;
        let policy_root = decode_delegation(
            std::str::from_utf8(&policy_root.authorization_bytes)
                .map_err(|_| "policy-root-invalid")?,
        )
        .map_err(|_| "policy-root-invalid")?;
        let enforcement_root = decode_delegation(
            std::str::from_utf8(&enforcement_root.authorization_bytes)
                .map_err(|_| "enforcement-root-invalid")?,
        )
        .map_err(|_| "enforcement-root-invalid")?;
        for key in [
            "ownerDid",
            "policyId",
            "policyDigestHex",
            "contentSourceDigestHex",
            "capabilityCeilingHashHex",
            "nativeProjectionHashHex",
        ] {
            if fact(&session.0.delegation, key) != fact(&policy_root.0.delegation, key)
                || fact(&session.0.delegation, key) != fact(&enforcement_root.0.delegation, key)
            {
                return Err("policy-session-fact-index-mismatch");
            }
        }
        let authenticated_enforcer = self
            .authenticated_registration_enforcer(&registration, now)
            .await?;
        if fact(&session.0.delegation, "enforcerDid") != Some(authenticated_enforcer.as_str())
            || fact(&session.0.delegation, "enforcerDid")
                != fact(&enforcement_root.0.delegation, "enforcerDid")
            || fact(&session.0.delegation, "nodeAudience") != Some(self.node_did.as_str())
            || fact(&session.0.delegation, "recipientDid") != Some(session.0.delegate.as_str())
        {
            return Err("policy-session-principal-binding-mismatch");
        }
        for root_cid in [
            registration.policy_root_cid,
            registration.enforcement_root_cid,
        ] {
            let root = policy_v3_root::Entity::find_by_id(root_cid.clone())
                .one(&self.conn)
                .await
                .map_err(|_| "policy-root-unavailable")?
                .ok_or("policy-root-missing")?;
            validate_persisted_root(&root, &root_cid, &registration.policy_cid, &self.node_did)
                .await?;
            let root_hash = tinycloud_auth::ipld_core::cid::Cid::try_from(root_cid.as_str())
                .map_err(|_| "policy-root-invalid")?;
            let graph_root =
                delegation_model::Entity::find_by_id(tinycloud_core::hash::Hash::from(root_hash))
                    .one(&self.conn)
                    .await
                    .map_err(|_| "policy-root-unavailable")?
                    .ok_or("policy-root-graph-missing")?;
            if graph_root.serialization != root.authorization_bytes {
                return Err("policy-root-graph-mismatch");
            }
            validate_stored_root_status(&root, &root_cid, &self.node_did, now, true)?;
        }
        Ok(true)
    }

    async fn is_policy_protected_parent(
        &self,
        cid: tinycloud_auth::ipld_core::cid::Cid,
    ) -> Result<bool, &'static str> {
        let cid_string = cid.to_string();
        if policy_v3_session::Entity::find_by_id(cid_string.clone())
            .one(&self.conn)
            .await
            .map_err(|_| "policy-session-unavailable")?
            .is_some()
            || policy_v3_root::Entity::find_by_id(cid_string)
                .one(&self.conn)
                .await
                .map_err(|_| "policy-root-unavailable")?
                .is_some()
        {
            return Ok(true);
        }

        let row = delegation_model::Entity::find_by_id(tinycloud_core::hash::Hash::from(cid))
            .one(&self.conn)
            .await
            .map_err(|_| "policy-session-unavailable")?;
        Ok(row.and_then(|row| row.facts).is_some_and(|facts| {
            facts.0.contains_key("xyz.tinycloud.policy/session-fact")
                || facts.0.contains_key("xyz.tinycloud.policy/root-profile")
        }))
    }

    /// Walk a policy chain from exact stored Authorization bytes. Every
    /// descendant is checked against its immediate signed parent; only S0 has
    /// a session index row. Database abilities, facts, and edges are checked
    /// as projections and can never substitute for the signed bytes.
    async fn validate_policy_chain(
        &self,
        tinycloud: &crate::TinyCloud,
        start: tinycloud_auth::ipld_core::cid::Cid,
    ) -> Result<(policy_v3_session::Model, Delegation), &'static str> {
        let mut current_cid = start;
        let mut child: Option<Delegation> = None;
        let mut visited = std::collections::HashSet::new();
        for _ in 0..=8 {
            if !visited.insert(current_cid.to_string()) {
                return Err("policy-session-cycle");
            }
            let Some((row, event)) = tinycloud
                .load_signed_delegation(current_cid)
                .await
                .map_err(|_| "policy-session-invalid")?
            else {
                return Err("policy-session-parent-missing");
            };
            verify_signed_delegation(&event.0.delegation)
                .await
                .map_err(|_| "policy-session-signature-invalid")?;
            self.validate_graph_projection(&row, &event).await?;
            if !is_policy_session(&event.0) {
                return Err("policy-session-protected-fact-missing");
            }
            if let Some(child) = child.as_ref() {
                if child.0.delegator != event.0.delegate
                    || !descendant_time_is_narrower(&child.0, &event.0)
                    || !descendant_profile_is_inherited(&child.0, &event.0)
                    || !capabilities_are_contained(&child.0.capabilities, &event.0.capabilities)
                {
                    return Err("policy-session-descendant-invalid");
                }
            }
            if event.0.parents.len() == 2 {
                let session_cid = event.content_hash().to_cid(0x55).to_string();
                let index = policy_v3_session::Entity::find_by_id(session_cid.clone())
                    .one(&self.conn)
                    .await
                    .map_err(|_| "policy-session-unavailable")?
                    .ok_or("policy-session-index-missing")?;
                if index.state != "admitted"
                    || index.session_cid != session_cid
                    || index.authorization_bytes != event.serialized_bytes()
                    || index.recipient_did != event.0.delegate
                    || fact(&event.0.delegation, "claimJti") != Some(index.claim_jti.as_str())
                    || fact(&event.0.delegation, "claimDigestHex")
                        != Some(index.claim_digest_hex.as_str())
                    || fact(&event.0.delegation, "vpDigestHex")
                        != Some(index.vp_digest_hex.as_str())
                    || event.0.not_before.map(format_time).as_deref()
                        != Some(index.not_before.as_str())
                    || event.0.expiry.map(format_time).as_deref() != Some(index.expires_at.as_str())
                {
                    return Err("policy-session-index-mismatch");
                }
                let registration =
                    policy_v3_registration::Entity::find_by_id(index.policy_cid.clone())
                        .one(&self.conn)
                        .await
                        .map_err(|_| "policy-registration-unavailable")?
                        .ok_or("policy-registration-missing")?;
                validate_registration_projection(&registration)
                    .map_err(|_| "policy-registration-projection-mismatch")?;
                let proofs = event
                    .0
                    .parents
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                if proofs
                    != [
                        registration.policy_root_cid.clone(),
                        registration.enforcement_root_cid.clone(),
                    ]
                    || fact(&event.0.delegation, "policyCid")
                        != Some(registration.policy_cid.as_str())
                {
                    return Err("policy-session-proof-index-mismatch");
                }
                self.authorize_roots(&registration, OffsetDateTime::now_utc())
                    .await?;
                for root_cid in event.0.parents.iter().copied() {
                    let Some((_, root)) = tinycloud
                        .load_signed_delegation(root_cid)
                        .await
                        .map_err(|_| "policy-root-invalid")?
                    else {
                        return Err("policy-root-missing");
                    };
                    if !capabilities_are_contained(&event.0.capabilities, &root.0.capabilities) {
                        return Err("policy-session-capability-widening");
                    }
                }
                return Ok((index, event));
            }
            if event.0.parents.len() != 1 {
                return Err("policy-session-parent-count-invalid");
            }
            child = Some(event);
            current_cid = child.as_ref().unwrap().0.parents[0];
        }
        Err("policy-session-depth-exceeded")
    }

    async fn validate_graph_projection(
        &self,
        row: &delegation_model::Model,
        event: &Delegation,
    ) -> Result<(), &'static str> {
        if row.delegator != event.0.delegator
            || row.delegatee != event.0.delegate
            || row.expiry != event.0.expiry
            || row.not_before != event.0.not_before
        {
            return Err("policy-session-row-projection-mismatch");
        }
        let expected_fact = match &event.0.delegation {
            TinyCloudDelegation::Ucan(ucan) => {
                ucan.payload().facts.as_ref().and_then(|f| f.first())
            }
            _ => None,
        };
        if row
            .facts
            .as_ref()
            .and_then(|facts| facts.0.get("xyz.tinycloud.policy/session-fact"))
            != expected_fact
        {
            return Err("policy-session-fact-projection-mismatch");
        }
        let stored = abilities::Entity::find()
            .filter(abilities::Column::Delegation.eq(row.id))
            .all(&self.conn)
            .await
            .map_err(|_| "policy-session-unavailable")?;
        let mut stored = stored
            .into_iter()
            .map(|ability| {
                canonical_json_value(&serde_json::json!({
                    "resource": ability.resource,
                    "ability": ability.ability,
                    "caveats": ability.caveats,
                }))
            })
            .collect::<Vec<_>>();
        let mut signed = event
            .0
            .capabilities
            .iter()
            .map(|capability| canonical_json_value(&serde_json::to_value(capability).unwrap()))
            .collect::<Vec<_>>();
        stored.sort();
        signed.sort();
        if stored != signed {
            return Err("policy-session-ability-projection-mismatch");
        }
        let mut stored_parents = parent_delegations::Entity::find()
            .filter(parent_delegations::Column::Child.eq(row.id))
            .all(&self.conn)
            .await
            .map_err(|_| "policy-session-unavailable")?
            .into_iter()
            .map(|link| link.parent.to_cid(0x55).to_string())
            .collect::<Vec<_>>();
        let mut signed_parents = event
            .0
            .parents
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        stored_parents.sort();
        signed_parents.sort();
        if stored_parents != signed_parents {
            return Err("policy-session-edge-projection-mismatch");
        }
        Ok(())
    }
}

fn capabilities_are_contained(
    child: &[tinycloud_core::util::Capability],
    parent: &[tinycloud_core::util::Capability],
) -> bool {
    child.iter().all(|candidate| {
        parent.iter().any(|ceiling| {
            candidate.resource.extends(&ceiling.resource)
                && tinycloud_core::policy_capability::ability_matches(
                    ceiling.ability.as_ref().as_ref(),
                    candidate.ability.as_ref().as_ref(),
                )
                && tinycloud_core::policy_capability::selector_caveats_contain(
                    &ceiling.caveats.0,
                    &candidate.caveats.0,
                )
                .unwrap_or(candidate.caveats == ceiling.caveats)
        })
    })
}

async fn validate_persisted_root(
    root: &policy_v3_root::Model,
    root_cid: &str,
    policy_cid: &str,
    node_did: &str,
) -> Result<(), &'static str> {
    let encoded =
        std::str::from_utf8(&root.authorization_bytes).map_err(|_| "policy-root-invalid")?;
    let event = decode_delegation(encoded).map_err(|_| "policy-root-invalid")?;
    if event.serialized_bytes() != root.authorization_bytes.as_slice()
        || event.content_hash().to_cid(0x55).to_string() != root_cid
        || !event.0.parents.is_empty()
        || fact(&event.0.delegation, "policyCid") != Some(policy_cid)
        || fact(&event.0.delegation, "nodeAudience") != Some(node_did)
    {
        return Err("policy-root-projection-mismatch");
    }
    if !is_policy_root(&event.0.delegation) {
        return Err("policy-root-fact-schema-invalid");
    }
    let expected_role = match root.role.as_str() {
        "policy-authority" | "policy-enforcement" => root.role.as_str(),
        _ => return Err("policy-root-role-invalid"),
    };
    if fact(&event.0.delegation, "role") != Some(expected_role) {
        return Err("policy-root-role-invalid");
    }
    verify_signed_delegation(&event.0.delegation)
        .await
        .map_err(|_| "policy-root-signature-invalid")
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterRequest {
    pub policy_cid: String,
    pub policy: Value,
    pub policy_root: String,
    pub enforcement_root: String,
    pub content_source_digest_hex: String,
    pub native_projection_hash_hex: String,
    pub attested_enforcer_binding: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponse {
    pub policy_cid: String,
    pub policy_root_cid: String,
    pub enforcement_root_cid: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnforcerBindingRequest {
    pub root_expires_at: String,
    #[serde(default)]
    pub enforcer_did: Option<String>,
}

#[post("/share/v3/enforcer-bindings", format = "json", data = "<request>")]
pub async fn issue_enforcer_binding(
    request: Json<EnforcerBindingRequest>,
    runtime: &State<PolicyV3Runtime>,
) -> Result<Json<Value>, (Status, String)> {
    let request = request.into_inner();
    let now = OffsetDateTime::now_utc();
    let root_expiry = parse_time(&request.root_expires_at)
        .map_err(|_| (Status::BadRequest, "enforcer-binding-time-invalid".into()))?;
    if format_time(root_expiry) != request.root_expires_at || root_expiry <= now {
        return Err((Status::BadRequest, "enforcer-binding-time-invalid".into()));
    }
    // The binding is embedded in the immutable v3 envelope and revalidated at
    // mint time. It therefore covers the requested root lifetime; root
    // liveness itself remains bounded by independently renewable 300-second
    // status checkpoints.
    let expires = root_expiry;
    let enforcer_did = request
        .enforcer_did
        .as_deref()
        .unwrap_or(runtime.node_did.as_str());
    enforcer_did
        .parse::<DIDBuf>()
        .map_err(|_| (Status::BadRequest, "enforcer-did-invalid".into()))?;
    let binding_material = serde_json::json!({
        "enforcerDid": enforcer_did,
        "nodeAudience": runtime.node_did,
    });
    let mut value = serde_json::json!({
        "schema": ATTESTED_ENFORCER_V2_SCHEMA,
        "enforcerDid": enforcer_did,
        "nodeAudience": runtime.node_did,
        "attestationBindingDigestHex": hex::encode(Sha256::digest(canonical_json_value(&binding_material))),
        "issuedAt": format_time(now),
        "expiresAt": format_time(expires),
    });
    let mut signed = b"xyz.tinycloud.policy/AttestedEnforcerBinding/v2\0".to_vec();
    signed.extend_from_slice(&canonical_json_value(&value));
    let signature = runtime
        .signer
        .node_keypair()
        .sign(&Sha256::digest(signed))
        .map_err(|error| (Status::InternalServerError, error.to_string()))?;
    value["signature"] = serde_json::json!({
        "suite": "Ed25519",
        "signerDid": runtime.node_did,
        "value": base64::encode_config(signature, URL_SAFE_NO_PAD),
    });
    validate_attested_enforcer_binding(&value, enforcer_did, &runtime.node_did, root_expiry, now)?;
    Ok(Json(value))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChallengeRequest {
    pub policy_cid: String,
    pub recipient_did: String,
    #[serde(default)]
    pub requested_capabilities: Vec<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub nonce: String,
    pub policy_cid: String,
    pub recipient_did: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_audience: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintRequest {
    pub policy_cid: String,
    pub challenge_id: String,
    pub nonce: String,
    #[serde(default)]
    pub claim: Value,
    #[serde(default)]
    pub requirement: Value,
    #[serde(default)]
    pub credential: Value,
    /// CID returned by the ordinary `/delegate` import of the holder's active
    /// TinyCloud account session. This is only an address into Node's stored
    /// authorization graph; policy/v2 re-verifies the exact signed CACAO.
    #[serde(default)]
    pub account_authorization_cid: Option<String>,
    /// Exact recipient-owned credentials space covered by the account
    /// authorization. This is independent of the sender-owned content source.
    #[serde(default)]
    pub credential_space_id: Option<String>,
    #[serde(default)]
    pub presentation: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MintResponse {
    pub session_cid: String,
    pub authorization: String,
    pub admitted: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusRequest {
    pub root_cid: String,
    pub checkpoint: Value,
    #[serde(default)]
    pub revocation: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootRevocationRequest {
    pub revocation: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusRenewalRequest {
    pub root_cid: String,
    pub renewal: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponse {
    pub root_cid: String,
    pub sequence: i64,
    pub state: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusCheckpointResponse {
    pub root_cid: String,
    pub state: String,
    pub checkpoint: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation: Option<Value>,
}

#[post("/share/v3/policies", format = "json", data = "<request>")]
pub async fn register_policy(
    request: Json<RegisterRequest>,
    runtime: &State<PolicyV3Runtime>,
    tinycloud: &State<crate::TinyCloud>,
) -> Result<Json<RegisterResponse>, (Status, String)> {
    let request = request.into_inner();
    let policy_bytes = canonical_json(&request.policy)?;
    validate_policy_document(&request.policy, &policy_bytes, &request.policy_cid)?;
    let projections = registration_projections(&request.policy)?;
    if request.content_source_digest_hex != projections.content_source_digest_hex
        || request.native_projection_hash_hex != projections.native_projection_hash_hex
    {
        return Err((Status::Forbidden, "registration-projection-mismatch".into()));
    }
    let (policy_root_cid, policy_root) = decode_root(&request.policy_root)?;
    let (enforcement_root_cid, enforcement_root) = decode_root(&request.enforcement_root)?;
    verify_signed_delegation(&policy_root.0.delegation)
        .await
        .map_err(|_| (Status::Forbidden, "policy-root-signature-invalid".into()))?;
    verify_signed_delegation(&enforcement_root.0.delegation)
        .await
        .map_err(|_| {
            (
                Status::Forbidden,
                "enforcement-root-signature-invalid".into(),
            )
        })?;
    if !is_policy_root(&policy_root.0.delegation) || !is_policy_root(&enforcement_root.0.delegation)
    {
        return Err((Status::Forbidden, "root-fact-schema-invalid".into()));
    }
    validate_root_pair(
        &request,
        &policy_root.0,
        &enforcement_root.0,
        &runtime.node_did,
        &projections,
    )?;
    let attested_enforcer_binding_bytes = validate_attested_enforcer_binding(
        &request.attested_enforcer_binding,
        fact(&enforcement_root.0.delegation, "enforcerDid")
            .ok_or((Status::Forbidden, "enforcer-binding-invalid".into()))?,
        &runtime.node_did,
        enforcement_root
            .0
            .expiry
            .ok_or((Status::Forbidden, "enforcement-root-expiry-missing".into()))?,
        OffsetDateTime::now_utc(),
    )?;
    let policy_digest_hex = policy_digest_hex(&request.policy)?;
    if fact(&policy_root.0.delegation, "policyDigestHex") != Some(policy_digest_hex.as_str())
        || fact(&enforcement_root.0.delegation, "policyDigestHex")
            != Some(policy_digest_hex.as_str())
        || fact(&policy_root.0.delegation, "ownerDid")
            != request.policy.get("ownerDid").and_then(Value::as_str)
        || fact(&enforcement_root.0.delegation, "ownerDid")
            != request.policy.get("ownerDid").and_then(Value::as_str)
    {
        return Err((Status::Forbidden, "policy-digest-mismatch".into()));
    }
    if let Some(existing) = policy_v3_registration::Entity::find_by_id(request.policy_cid.clone())
        .one(&runtime.conn)
        .await
        .map_err(db_error)?
    {
        if existing.policy_bytes == policy_bytes
            && existing.policy_root_cid == policy_root_cid
            && existing.enforcement_root_cid == enforcement_root_cid
        {
            return Ok(Json(RegisterResponse {
                policy_cid: request.policy_cid,
                policy_root_cid,
                enforcement_root_cid,
            }));
        }
        return Err((Status::Conflict, "policy-registration-conflict".into()));
    }

    let now = OffsetDateTime::now_utc();
    let policy_status = initial_status_checkpoint(
        runtime,
        &policy_root_cid,
        "policy-authority",
        &policy_root.0.delegation,
        now,
    )?;
    let enforcement_status = initial_status_checkpoint(
        runtime,
        &enforcement_root_cid,
        "policy-enforcement",
        &enforcement_root.0.delegation,
        now,
    )?;

    let registration = policy_v3_registration::ActiveModel {
        policy_cid: Set(request.policy_cid.clone()),
        policy_bytes: Set(policy_bytes.clone()),
        policy_digest_hex: Set(policy_digest_hex),
        owner_did: Set(fact(
            &decode_delegation(&request.policy_root)?.0.delegation,
            "ownerDid",
        )
        .unwrap_or_default()
        .to_owned()),
        policy_root_cid: Set(policy_root_cid.clone()),
        enforcement_root_cid: Set(enforcement_root_cid.clone()),
        content_source_digest_hex: Set(projections.content_source_digest_hex),
        native_projection_hash_hex: Set(projections.native_projection_hash_hex),
        attested_enforcer_binding_bytes: Set(attested_enforcer_binding_bytes),
        registered_at: Set(format_time(now)),
        expires_at: Set(root_expiry(&request.policy_root)
            .unwrap_or_else(|_| format_time(now + Duration::seconds(MAX_SESSION_TTL_SECONDS)))),
    };
    let _writer = match &runtime.sqlite_writer_lock {
        Some(lock) => Some(lock.lock().await),
        None => None,
    };
    let txn = runtime.conn.begin().await.map_err(db_error)?;
    // The normal graph rows, abilities, and signed-byte projections share one
    // SQL transaction. A failure in either side leaves no partial authority.
    tinycloud
        .delegate_batch_in_transaction(
            &txn,
            vec![
                decode_delegation(&request.policy_root)?,
                decode_delegation(&request.enforcement_root)?,
            ],
        )
        .await
        .map_err(|error| (Status::Forbidden, error.to_string()))?;
    registration
        .insert(&txn)
        .await
        .map_err(|e| (Status::Conflict, e.to_string()))?;
    for (cid, role, bytes, status) in [
        (
            policy_root_cid.clone(),
            "policy-authority",
            request.policy_root.into_bytes(),
            policy_status,
        ),
        (
            enforcement_root_cid.clone(),
            "policy-enforcement",
            request.enforcement_root.into_bytes(),
            enforcement_status,
        ),
    ] {
        let checked_at = status_field(&status, "checkedAt")
            .ok_or((Status::InternalServerError, "status-invalid".into()))?;
        let fresh_until = status_field(&status, "freshUntil")
            .ok_or((Status::InternalServerError, "status-invalid".into()))?;
        policy_v3_root::ActiveModel {
            root_cid: Set(cid),
            policy_cid: Set(request.policy_cid.clone()),
            role: Set(role.to_owned()),
            authorization_bytes: Set(bytes),
            status_checkpoint_bytes: Set(Some(status)),
            previous_checkpoint_digest_hex: Set(None),
            status_sequence: Set(1),
            admission_epoch: Set(0),
            status_checked_at: Set(Some(checked_at)),
            status_fresh_until: Set(Some(fresh_until)),
            revoked_at: Set(None),
            revocation_bytes: Set(None),
        }
        .insert(&txn)
        .await
        .map_err(|e| (Status::Conflict, e.to_string()))?;
    }
    txn.commit().await.map_err(db_error)?;
    Ok(Json(RegisterResponse {
        policy_cid: request.policy_cid,
        policy_root_cid,
        enforcement_root_cid,
    }))
}

#[post("/share/v3/policy/challenges", format = "json", data = "<request>")]
pub async fn challenge(
    request: Json<ChallengeRequest>,
    runtime: &State<PolicyV3Runtime>,
) -> Result<Json<ChallengeResponse>, (Status, String)> {
    let request = request.into_inner();
    let registration = policy_v3_registration::Entity::find_by_id(request.policy_cid.clone())
        .one(&runtime.conn)
        .await
        .map_err(db_error)?
        .ok_or((Status::NotFound, "policy-registration-missing".into()))?;
    let policy = validate_registration_projection(&registration)?;
    runtime
        .authorize_roots(&registration, OffsetDateTime::now_utc())
        .await
        .map_err(|error| (Status::Forbidden, error.into()))?;
    request
        .recipient_did
        .parse::<DIDBuf>()
        .map_err(|_| (Status::BadRequest, "recipient-did-invalid".into()))?;
    let requested_capabilities = validate_requested_policy_capabilities(
        &request.requested_capabilities,
        policy
            .get("capabilityCeiling")
            .and_then(Value::as_array)
            .ok_or((Status::Forbidden, "policy-registration-corrupt".into()))?,
    )?;
    let mut nonce_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = base64::encode_config(nonce_bytes, URL_SAFE_NO_PAD);
    let mut challenge_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut challenge_bytes);
    let challenge_id = format!("pec_{}", hex::encode(challenge_bytes));
    let now = OffsetDateTime::now_utc();
    let expires_at = now + Duration::seconds(300);
    policy_v3_challenge::ActiveModel {
        challenge_id: Set(challenge_id.clone()),
        policy_cid: Set(request.policy_cid.clone()),
        recipient_did: Set(request.recipient_did.clone()),
        nonce_hash_hex: Set(hex::encode(Sha256::digest(nonce.as_bytes()))),
        requested_capabilities: Set(Value::Array(requested_capabilities)),
        issued_at: Set(format_time(now)),
        expires_at: Set(format_time(expires_at)),
        consumed_at: Set(None),
    }
    .insert(&runtime.conn)
    .await
    .map_err(db_error)?;
    Ok(Json(ChallengeResponse {
        challenge_id,
        nonce,
        policy_cid: request.policy_cid,
        recipient_did: request.recipient_did,
        expires_at: format_time(expires_at),
        node_audience: (policy.get("schema").and_then(Value::as_str) == Some(POLICY_V2_SCHEMA))
            .then(|| runtime.node_did.clone()),
    }))
}

#[post("/share/v3/policy/delegations", format = "json", data = "<request>")]
pub async fn mint(
    request: Json<MintRequest>,
    runtime: &State<PolicyV3Runtime>,
    tinycloud: &State<crate::TinyCloud>,
) -> Result<Json<MintResponse>, (Status, String)> {
    let request = request.into_inner();
    let challenge = policy_v3_challenge::Entity::find_by_id(request.challenge_id.clone())
        .one(&runtime.conn)
        .await
        .map_err(db_error)?
        .ok_or((Status::NotFound, "challenge-not-found".into()))?;
    let now = OffsetDateTime::now_utc();
    if challenge.policy_cid != request.policy_cid
        || parse_time(&challenge.expires_at).map_err(bad)? <= now
        || hex::encode(Sha256::digest(request.nonce.as_bytes())) != challenge.nonce_hash_hex
    {
        return Err((Status::Unauthorized, "challenge-invalid".into()));
    }
    if request.presentation.is_null() {
        return Err((Status::BadRequest, "presentation-required".into()));
    }
    let registration = policy_v3_registration::Entity::find_by_id(request.policy_cid.clone())
        .one(&runtime.conn)
        .await
        .map_err(db_error)?
        .ok_or((Status::NotFound, "policy-registration-missing".into()))?;
    let registered_policy = validate_registration_projection(&registration)?;
    let credential_admission =
        registered_policy.get("schema").and_then(Value::as_str) == Some(POLICY_V2_SCHEMA);
    if credential_admission {
        if request.requirement.is_null()
            || request.credential.is_null()
            || !request.claim.is_null()
            || request.account_authorization_cid.is_none()
            || request.credential_space_id.is_none()
        {
            return Err((
                Status::BadRequest,
                "credential-admission-request-invalid".into(),
            ));
        }
    } else if request.claim.is_null()
        || !request.requirement.is_null()
        || !request.credential.is_null()
        || request.account_authorization_cid.is_some()
        || request.credential_space_id.is_some()
    {
        return Err((Status::BadRequest, "claim-and-presentation-required".into()));
    }
    let policy_root = policy_v3_root::Entity::find_by_id(registration.policy_root_cid.clone())
        .one(&runtime.conn)
        .await
        .map_err(db_error)?
        .ok_or((Status::Forbidden, "policy-root-missing".into()))?;
    let policy_root = decode_delegation(
        std::str::from_utf8(&policy_root.authorization_bytes)
            .map_err(|_| (Status::Forbidden, "policy-root-invalid".into()))?,
    )?;
    let enforcement_root =
        policy_v3_root::Entity::find_by_id(registration.enforcement_root_cid.clone())
            .one(&runtime.conn)
            .await
            .map_err(db_error)?
            .ok_or((Status::Forbidden, "policy-root-missing".into()))?;
    let enforcement_root = decode_delegation(
        std::str::from_utf8(&enforcement_root.authorization_bytes)
            .map_err(|_| (Status::Forbidden, "policy-root-invalid".into()))?,
    )?;
    let enforcer_did = fact(&enforcement_root.0.delegation, "enforcerDid")
        .ok_or((Status::Forbidden, "sibling-root-mismatch".into()))?;
    runtime
        .authorize_roots(&registration, now)
        .await
        .map_err(|e| (Status::Forbidden, e.into()))?;
    for (cid, expected) in [
        (&registration.policy_root_cid, &policy_root),
        (&registration.enforcement_root_cid, &enforcement_root),
    ] {
        let parsed_cid = cid
            .parse()
            .map_err(|_| (Status::Forbidden, "policy-root-invalid".into()))?;
        let Some((_, graph_root)) = tinycloud
            .load_signed_delegation(parsed_cid)
            .await
            .map_err(|_| (Status::Forbidden, "policy-root-graph-invalid".into()))?
        else {
            return Err((Status::Forbidden, "policy-root-graph-missing".into()));
        };
        if graph_root.serialized_bytes() != expected.serialized_bytes() {
            return Err((Status::Forbidden, "policy-root-graph-mismatch".into()));
        }
    }

    let policy_owner_did = fact(&policy_root.0.delegation, "ownerDid")
        .ok_or((Status::Forbidden, "policy-owner-missing".into()))?;
    let requested = challenge
        .requested_capabilities
        .as_array()
        .ok_or((Status::Forbidden, "requested-capabilities-invalid".into()))?;
    let account_owner_proof = if credential_admission {
        Some(
            authenticate_account_owner(
                request.account_authorization_cid.as_deref(),
                request.credential_space_id.as_deref(),
                &challenge.recipient_did,
                runtime,
                tinycloud,
            )
            .await?,
        )
    } else {
        None
    };
    let claim_context = ClaimPresentationContext {
        challenge_id: &request.challenge_id,
        nonce: &request.nonce,
        policy_cid: &request.policy_cid,
        owner_did: policy_owner_did,
        recipient_did: &challenge.recipient_did,
        authenticated_account_owner: account_owner_proof
            .as_ref()
            .map(|proof| proof.owner_did.as_str()),
        now,
    };
    let admission_v3 = if credential_admission {
        Some(validate_credential_admission_v3(
            &request.requirement,
            &request.credential,
            &request.presentation,
            &registered_policy,
            &claim_context,
            runtime,
            requested,
        )?)
    } else {
        validate_claim_and_presentation(&request.claim, &request.presentation, &claim_context)?;
        if request
            .presentation
            .get("holderDid")
            .and_then(Value::as_str)
            != Some(challenge.recipient_did.as_str())
            || request.claim.get("holderDid").and_then(Value::as_str)
                != Some(challenge.recipient_did.as_str())
        {
            return Err((Status::Forbidden, "recipient-binding-invalid".into()));
        }
        None
    };
    // This is the in-process evaluator boundary. It returns an opaque value
    // consumed below; no caller-supplied Authorization or serialized decision
    // can construct the mint transition by itself.
    let evaluation_context = CurrentAllowContext {
        challenge: &challenge,
        policy_root: &policy_root.0.delegation,
        enforcement_root: &enforcement_root.0.delegation,
        policy_root_cid: &registration.policy_root_cid,
        enforcement_root_cid: &registration.enforcement_root_cid,
        node_did: &runtime.node_did,
        now,
    };
    let allow = evaluate_current_allow(
        (!credential_admission).then_some(&request.claim),
        &request.presentation,
        &evaluation_context,
    )?;
    validate_requested_policy_capabilities(
        requested,
        registered_policy
            .get("capabilityCeiling")
            .and_then(Value::as_array)
            .ok_or((Status::Forbidden, "policy-registration-corrupt".into()))?,
    )?;
    let (claim_jti, claim_digest, vp_digest, credential_evidence_digest) =
        if let Some(admission) = admission_v3.as_ref() {
            (
                admission.credential_id.as_str(),
                admission.envelope_digest_hex.clone(),
                admission.presentation_digest_hex.clone(),
                hex::encode(
                    decode_config(&admission.credential_digest, URL_SAFE_NO_PAD)
                        .map_err(|_| (Status::Forbidden, "credential-digest-invalid".into()))?,
                ),
            )
        } else {
            let claim_jti = request
                .claim
                .get("jti")
                .and_then(Value::as_str)
                .ok_or((Status::Forbidden, "claim-jti-missing".into()))?;
            let vp_bytes = decode_config(
                request
                    .presentation
                    .get("vpBytesBase64")
                    .and_then(Value::as_str)
                    .ok_or((Status::Forbidden, "presentation-bytes-missing".into()))?,
                URL_SAFE_NO_PAD,
            )
            .map_err(|_| (Status::Forbidden, "presentation-bytes-invalid".into()))?;
            let evidence = request
                .claim
                .get("credentialEvidence")
                .map(credential_evidence_digest)
                .transpose()?
                .ok_or((Status::Forbidden, "credential-evidence-missing".into()))?;
            (
                claim_jti,
                digest_value(&request.claim),
                hex::encode(Sha256::digest(vp_bytes)),
                evidence,
            )
        };
    let mut facts = serde_json::Map::new();
    for key in [
        "ownerDid",
        "policyId",
        "policyDigestHex",
        "contentSourceDigestHex",
        "capabilityCeilingHashHex",
        "nativeProjectionHashHex",
    ] {
        let value = fact(&policy_root.0.delegation, key)
            .or_else(|| fact(&enforcement_root.0.delegation, key))
            .ok_or((Status::Forbidden, "sibling-root-mismatch".into()))?;
        facts.insert(key.to_owned(), Value::String(value.to_owned()));
    }
    let decision_context_digest = allow._decision_context_digest_hex;
    let mut issuance_audit = serde_json::json!({
        "challengeId": request.challenge_id,
        "claimDigestHex": claim_digest.clone(),
        "vpDigestHex": vp_digest.clone(),
        "decisionContextDigestHex": decision_context_digest.clone(),
    });
    if let Some(admission) = admission_v3.as_ref() {
        issuance_audit["credentialSpaceOwnerDid"] =
            Value::String(admission.credential_space_owner_did.clone());
    }
    let issuance_audit_digest = digest_value(&issuance_audit);
    for (key, value) in [
        ("profile", POLICY_SESSION_PROFILE.to_owned()),
        ("policyCid", request.policy_cid.clone()),
        ("policyDelegationCid", registration.policy_root_cid.clone()),
        (
            "enforcementDelegationCid",
            registration.enforcement_root_cid.clone(),
        ),
        ("enforcerDid", enforcer_did.to_owned()),
        ("nodeAudience", runtime.node_did.clone()),
        ("recipientDid", challenge.recipient_did.clone()),
        ("challengeId", request.challenge_id.clone()),
        ("claimDigestHex", claim_digest.clone()),
        ("claimJti", claim_jti.to_owned()),
        ("vpDigestHex", vp_digest.clone()),
        ("credentialEvidenceDigestHex", credential_evidence_digest),
        ("decisionContextDigestHex", decision_context_digest),
        ("issuanceAuditDigestHex", issuance_audit_digest),
    ] {
        facts.insert(key.to_owned(), Value::String(value));
    }
    facts.insert("remainingRedelegationDepth".to_owned(), Value::from(8_u64));
    let not_before = now.unix_timestamp();
    let expires = (now + Duration::seconds(MAX_SESSION_TTL_SECONDS)).unix_timestamp();
    if expires <= not_before {
        return Err((Status::Forbidden, "session-time-invalid".into()));
    }
    let node_keypair = runtime.signer.node_keypair();
    let node_public_key = node_keypair
        .public()
        .try_into_ed25519()
        .map_err(|error| (Status::InternalServerError, error.to_string()))?
        .to_bytes();
    let header = serde_json::json!({
        "alg": "EdDSA",
        "jwk": {
            "alg": "EdDSA",
            "crv": "Ed25519",
            "kty": "OKP",
            "x": encode_config(node_public_key, URL_SAFE_NO_PAD),
        },
        "typ": "JWT",
        "ucv": "0.10.0",
    });
    let payload = serde_json::json!({
        "att": attenuation_for_policy_capabilities(&allow.approved_capabilities)?,
        "aud": challenge.recipient_did,
        "exp": expires,
        "fct": [Value::Object(facts)],
        "iss": runtime.node_did,
        "nbf": not_before,
        "nnc": request.nonce,
        "prf": [registration.policy_root_cid, registration.enforcement_root_cid],
    });
    let header_segment = encode_config(canonical_json_value(&header), URL_SAFE_NO_PAD);
    let payload_segment = encode_config(canonical_json_value(&payload), URL_SAFE_NO_PAD);
    let signing_input = format!("{header_segment}.{payload_segment}");
    let signature = node_keypair
        .sign(signing_input.as_bytes())
        .map_err(|error| (Status::InternalServerError, error.to_string()))?;
    let encoded = format!(
        "{signing_input}.{}",
        encode_config(signature, URL_SAFE_NO_PAD)
    );
    let event = decode_delegation(&encoded)?;
    let session = &event.0;
    if !is_policy_session(session) || session.parents.len() != 2 {
        return Err((
            Status::InternalServerError,
            "node-minted-profile-invalid".into(),
        ));
    }
    let session_cid = event.content_hash().to_cid(0x55).to_string();
    let session_bytes = event.serialized_bytes().to_vec();
    let session_model = policy_v3_session::ActiveModel {
        session_cid: Set(session_cid.clone()),
        policy_cid: Set(request.policy_cid.clone()),
        authorization_bytes: Set(session_bytes.clone()),
        recipient_did: Set(session.delegate.clone()),
        claim_jti: Set(claim_jti.to_owned()),
        claim_digest_hex: Set(claim_digest.clone()),
        vp_digest_hex: Set(vp_digest.clone()),
        state: Set("admitted".into()),
        not_before: Set(session
            .not_before
            .map(format_time)
            .unwrap_or_else(|| format_time(now))),
        expires_at: Set(session
            .expiry
            .map(format_time)
            .ok_or((Status::Forbidden, "session-expiry-missing".into()))?),
        admitted_at: Set(Some(format_time(now))),
    };
    // Challenge/JTI consumption, the exact S0 graph rows (delegation,
    // abilities, ordered signed proofs), and the admitted session index are a
    // single SQL commit. Any failure rolls the whole transition back.
    let _writer = match &runtime.sqlite_writer_lock {
        Some(lock) => Some(lock.lock().await),
        None => None,
    };
    let txn = runtime.conn.begin().await.map_err(db_error)?;
    if let Some(proof) = account_owner_proof.as_ref() {
        validate_locked_account_owner(&txn, proof).await?;
    }
    let locked_challenge = policy_v3_challenge::Entity::find_by_id(request.challenge_id.clone())
        .lock_exclusive()
        .one(&txn)
        .await
        .map_err(db_error)?
        .ok_or((Status::Unauthorized, "challenge-invalid".into()))?;
    if locked_challenge.policy_cid != challenge.policy_cid
        || locked_challenge.recipient_did != challenge.recipient_did
        || locked_challenge.nonce_hash_hex != challenge.nonce_hash_hex
        || locked_challenge.requested_capabilities != challenge.requested_capabilities
        || locked_challenge.issued_at != challenge.issued_at
        || locked_challenge.expires_at != challenge.expires_at
        || locked_challenge.consumed_at.is_some()
        || parse_time(&locked_challenge.expires_at).map_err(bad)? <= now
        || hex::encode(Sha256::digest(request.nonce.as_bytes())) != locked_challenge.nonce_hash_hex
    {
        return Err((Status::Unauthorized, "challenge-invalid".into()));
    }
    let locked_registration =
        policy_v3_registration::Entity::find_by_id(registration.policy_cid.clone())
            .lock_exclusive()
            .one(&txn)
            .await
            .map_err(db_error)?
            .ok_or((Status::Conflict, "policy-registration-changed".into()))?;
    let locked_policy = validate_registration_projection(&locked_registration)?;
    if locked_registration.policy_bytes != registration.policy_bytes
        || locked_registration.policy_root_cid != registration.policy_root_cid
        || locked_registration.enforcement_root_cid != registration.enforcement_root_cid
        || locked_registration.attested_enforcer_binding_bytes
            != registration.attested_enforcer_binding_bytes
    {
        return Err((Status::Conflict, "policy-registration-changed".into()));
    }
    let mut locked_root_events = Vec::with_capacity(2);
    for root_cid in [
        &registration.policy_root_cid,
        &registration.enforcement_root_cid,
    ] {
        let root = policy_v3_root::Entity::find_by_id(root_cid.clone())
            .lock_exclusive()
            .one(&txn)
            .await
            .map_err(db_error)?
            .ok_or((Status::Forbidden, "policy-root-missing".into()))?;
        validate_persisted_root(&root, root_cid, &registration.policy_cid, &runtime.node_did)
            .await
            .map_err(|error| (Status::Forbidden, error.into()))?;
        validate_stored_root_status(&root, root_cid, &runtime.node_did, now, true)
            .map_err(|error| (Status::Forbidden, error.into()))?;
        let current_event = decode_delegation(
            std::str::from_utf8(&root.authorization_bytes)
                .map_err(|_| (Status::Forbidden, "policy-root-invalid".into()))?,
        )?;
        locked_root_events.push(current_event);
        if root.revoked_at.is_some()
            || root.revocation_bytes.is_some()
            || root
                .status_fresh_until
                .as_deref()
                .and_then(|value| parse_time(value).ok())
                .is_none_or(|fresh_until| fresh_until <= now)
        {
            return Err((Status::Conflict, "policy-root-state-changed".into()));
        }
        let locked = policy_v3_root::Entity::update_many()
            .col_expr(
                policy_v3_root::Column::AdmissionEpoch,
                Expr::value(root.admission_epoch + 1),
            )
            .filter(policy_v3_root::Column::RootCid.eq(root_cid.clone()))
            .filter(policy_v3_root::Column::AdmissionEpoch.eq(root.admission_epoch))
            .filter(policy_v3_root::Column::StatusSequence.eq(root.status_sequence))
            .filter(policy_v3_root::Column::RevokedAt.is_null())
            .filter(policy_v3_root::Column::RevocationBytes.is_null())
            .exec(&txn)
            .await
            .map_err(db_error)?;
        if locked.rows_affected != 1 {
            return Err((Status::Conflict, "policy-root-state-changed".into()));
        }
    }
    let locked_claim_context = ClaimPresentationContext {
        challenge_id: &request.challenge_id,
        nonce: &request.nonce,
        policy_cid: &request.policy_cid,
        owner_did: fact(&locked_root_events[0].0.delegation, "ownerDid")
            .ok_or((Status::Forbidden, "policy-owner-missing".into()))?,
        recipient_did: &locked_challenge.recipient_did,
        authenticated_account_owner: account_owner_proof
            .as_ref()
            .map(|proof| proof.owner_did.as_str()),
        now,
    };
    let locked_admission_v3 = if credential_admission {
        Some(validate_credential_admission_v3(
            &request.requirement,
            &request.credential,
            &request.presentation,
            &locked_policy,
            &locked_claim_context,
            runtime,
            locked_challenge
                .requested_capabilities
                .as_array()
                .ok_or((Status::Forbidden, "requested-capabilities-invalid".into()))?,
        )?)
    } else {
        validate_claim_and_presentation(
            &request.claim,
            &request.presentation,
            &locked_claim_context,
        )?;
        None
    };
    if admission_v3
        .as_ref()
        .zip(locked_admission_v3.as_ref())
        .is_some_and(|(before, after)| {
            before.credential_id != after.credential_id
                || before.credential_digest != after.credential_digest
                || before.envelope_digest_hex != after.envelope_digest_hex
                || before.presentation_digest_hex != after.presentation_digest_hex
                || before.credential_space_owner_did != after.credential_space_owner_did
        })
    {
        return Err((Status::Conflict, "credential-evaluation-changed".into()));
    }
    validate_requested_policy_capabilities(
        locked_challenge
            .requested_capabilities
            .as_array()
            .ok_or((Status::Forbidden, "requested-capabilities-invalid".into()))?,
        locked_policy
            .get("capabilityCeiling")
            .and_then(Value::as_array)
            .ok_or((Status::Forbidden, "policy-registration-corrupt".into()))?,
    )?;
    let final_allow = evaluate_current_allow(
        (!credential_admission).then_some(&request.claim),
        &request.presentation,
        &CurrentAllowContext {
            challenge: &locked_challenge,
            policy_root: &locked_root_events[0].0.delegation,
            enforcement_root: &locked_root_events[1].0.delegation,
            policy_root_cid: &locked_registration.policy_root_cid,
            enforcement_root_cid: &locked_registration.enforcement_root_cid,
            node_did: &runtime.node_did,
            now,
        },
    )?;
    if canonical_value_set(&final_allow.approved_capabilities)
        != canonical_value_set(&allow.approved_capabilities)
    {
        return Err((Status::Conflict, "policy-evaluation-changed".into()));
    }
    let reserved = policy_v3_challenge::Entity::update_many()
        .col_expr(
            policy_v3_challenge::Column::ConsumedAt,
            Expr::value(format_time(now)),
        )
        .filter(policy_v3_challenge::Column::ChallengeId.eq(request.challenge_id.clone()))
        .filter(policy_v3_challenge::Column::ConsumedAt.is_null())
        .exec(&txn)
        .await
        .map_err(db_error)?;
    if reserved.rows_affected != 1 {
        return Err((Status::Unauthorized, "challenge-invalid".into()));
    }

    session_model.insert(&txn).await.map_err(|_| {
        (
            Status::Conflict,
            "claim-jti-or-session-already-consumed".into(),
        )
    })?;
    tinycloud
        .delegate_batch_in_transaction(&txn, vec![event])
        .await
        .map_err(|error| (Status::Forbidden, error.to_string()))?;
    txn.commit().await.map_err(db_error)?;
    Ok(Json(MintResponse {
        session_cid,
        authorization: encoded,
        admitted: true,
    }))
}

impl PolicyV3Runtime {
    async fn authenticated_registration_enforcer(
        &self,
        registration: &policy_v3_registration::Model,
        now: OffsetDateTime,
    ) -> Result<String, &'static str> {
        let root = policy_v3_root::Entity::find_by_id(registration.enforcement_root_cid.clone())
            .one(&self.conn)
            .await
            .map_err(|_| "enforcement-root-unavailable")?
            .ok_or("enforcement-root-missing")?;
        let event = decode_delegation(
            std::str::from_utf8(&root.authorization_bytes)
                .map_err(|_| "enforcement-root-invalid")?,
        )
        .map_err(|_| "enforcement-root-invalid")?;
        let enforcer_did = fact(&event.0.delegation, "enforcerDid")
            .ok_or("enforcer-binding-invalid")?
            .to_owned();
        let binding: Value = serde_json::from_slice(&registration.attested_enforcer_binding_bytes)
            .map_err(|_| "enforcer-binding-invalid")?;
        validate_attested_enforcer_binding(
            &binding,
            &enforcer_did,
            &self.node_did,
            event.0.expiry.ok_or("enforcer-binding-invalid")?,
            now,
        )
        .map_err(|_| "enforcer-binding-invalid")?;
        Ok(enforcer_did)
    }

    async fn authorize_roots(
        &self,
        registration: &policy_v3_registration::Model,
        now: OffsetDateTime,
    ) -> Result<(), &'static str> {
        let policy = validate_registration_projection(registration)
            .map_err(|_| "policy-registration-projection-mismatch")?;
        let mut roots = Vec::new();
        for cid in [
            &registration.policy_root_cid,
            &registration.enforcement_root_cid,
        ] {
            let root = policy_v3_root::Entity::find_by_id(cid.clone())
                .one(&self.conn)
                .await
                .map_err(|_| "root-unavailable")?
                .ok_or("root-missing")?;
            validate_persisted_root(&root, cid, &registration.policy_cid, &self.node_did).await?;
            validate_stored_root_status(&root, cid, &self.node_did, now, true)?;
            let encoded = std::str::from_utf8(&root.authorization_bytes)
                .map_err(|_| "policy-root-invalid")?;
            roots.push(decode_delegation(encoded).map_err(|_| "policy-root-invalid")?);
        }
        let projections = registration_projections(&policy)
            .map_err(|_| "policy-registration-projection-mismatch")?;
        let request = RegisterRequest {
            policy_cid: registration.policy_cid.clone(),
            policy,
            policy_root: std::str::from_utf8(roots[0].serialized_bytes())
                .map_err(|_| "policy-root-invalid")?
                .to_owned(),
            enforcement_root: std::str::from_utf8(roots[1].serialized_bytes())
                .map_err(|_| "policy-root-invalid")?
                .to_owned(),
            content_source_digest_hex: registration.content_source_digest_hex.clone(),
            native_projection_hash_hex: registration.native_projection_hash_hex.clone(),
            attested_enforcer_binding: serde_json::from_slice(
                &registration.attested_enforcer_binding_bytes,
            )
            .map_err(|_| "enforcer-binding-invalid")?,
        };
        validate_root_pair(
            &request,
            &roots[0].0,
            &roots[1].0,
            &self.node_did,
            &projections,
        )
        .map_err(|_| "sibling-root-mismatch")?;
        validate_attested_enforcer_binding(
            &request.attested_enforcer_binding,
            fact(&roots[1].0.delegation, "enforcerDid").ok_or("enforcer-binding-invalid")?,
            &self.node_did,
            roots[1].0.expiry.ok_or("enforcer-binding-invalid")?,
            now,
        )
        .map_err(|_| "enforcer-binding-invalid")?;
        Ok(())
    }
}

fn validate_stored_root_status(
    root: &policy_v3_root::Model,
    root_cid: &str,
    node_did: &str,
    now: OffsetDateTime,
    require_fresh: bool,
) -> Result<(), &'static str> {
    if root.revoked_at.is_some() || root.revocation_bytes.is_some() {
        validate_stored_revocation(root, root_cid, node_did, now)?;
        return Err("root-revoked");
    }
    let bytes = root
        .status_checkpoint_bytes
        .as_deref()
        .ok_or("root-status-missing")?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "root-status-invalid")?;
    if canonical_json_value(&value) != bytes {
        return Err("root-status-not-canonical");
    }
    let object = value.as_object().ok_or("root-status-invalid")?;
    const STATUS_KEYS: &[&str] = &[
        "schema",
        "targetCid",
        "targetRole",
        "ownerDid",
        "nodeAudience",
        "state",
        "sequence",
        "checkedAt",
        "freshUntil",
        "revokedAt",
        "revocationCid",
        "previousCheckpointDigestHex",
        "issuerDid",
        "signature",
    ];
    if object
        .keys()
        .any(|key| !STATUS_KEYS.contains(&key.as_str()))
    {
        return Err("root-status-unknown-field");
    }
    if object.get("schema").and_then(Value::as_str) != Some(ROOT_STATUS_V1_SCHEMA)
        || object.get("targetCid").and_then(Value::as_str) != Some(root_cid)
        || object.get("targetRole").and_then(Value::as_str) != Some(root.role.as_str())
        || object.get("issuerDid").and_then(Value::as_str) != Some(node_did)
        || object.get("nodeAudience").and_then(Value::as_str) != Some(node_did)
        || object.get("state").and_then(Value::as_str) != Some("active")
        || object.get("sequence").and_then(Value::as_i64) != Some(root.status_sequence)
        || object.get("checkedAt").and_then(Value::as_str) != root.status_checked_at.as_deref()
        || object.get("freshUntil").and_then(Value::as_str) != root.status_fresh_until.as_deref()
        || object.get("state").and_then(Value::as_str) == Some("active")
            && (object.get("revokedAt").is_some() || object.get("revocationCid").is_some())
    {
        return Err("root-status-projection-mismatch");
    }
    let checked = parse_time(
        object
            .get("checkedAt")
            .and_then(Value::as_str)
            .ok_or("root-status-invalid")?,
    )
    .map_err(|_| "root-status-invalid")?;
    let fresh = parse_time(
        object
            .get("freshUntil")
            .and_then(Value::as_str)
            .ok_or("root-status-invalid")?,
    )
    .map_err(|_| "root-status-invalid")?;
    if checked > now
        || (require_fresh && fresh <= now)
        || fresh - checked > Duration::seconds(MAX_STATUS_AGE_SECONDS)
    {
        return Err("root-not-live");
    }
    let previous_digest = object
        .get("previousCheckpointDigestHex")
        .and_then(Value::as_str);
    if root.status_sequence == 1 {
        if previous_digest.is_some() {
            return Err("root-status-chain-invalid");
        }
    } else {
        if previous_digest != root.previous_checkpoint_digest_hex.as_deref() {
            return Err("root-status-chain-invalid");
        }
    }
    let signature = object
        .get("signature")
        .and_then(Value::as_object)
        .and_then(|signature| signature.get("signerDid"))
        .and_then(Value::as_str)
        .ok_or("root-status-signature-missing")?;
    if signature != node_did {
        return Err("root-status-signature-invalid");
    }
    let signature = object
        .get("signature")
        .and_then(Value::as_object)
        .and_then(|signature| signature.get("value"))
        .and_then(Value::as_str)
        .ok_or("root-status-signature-missing")?;
    if object
        .get("signature")
        .and_then(Value::as_object)
        .and_then(|signature| signature.get("suite"))
        .and_then(Value::as_str)
        != Some("Ed25519")
    {
        return Err("root-status-signature-invalid");
    }
    let signature =
        decode_config(signature, URL_SAFE_NO_PAD).map_err(|_| "root-status-signature-invalid")?;
    let mut unsigned = value;
    unsigned
        .as_object_mut()
        .ok_or("root-status-invalid")?
        .remove("signature");
    let mut signed = STATUS_DOMAIN.to_vec();
    signed.extend_from_slice(&canonical_json_value(&unsigned));
    let signed_digest = Sha256::digest(signed);
    tinycloud_auth::share_email_evidence::verify_detached_ed25519(
        node_did,
        &signed_digest,
        &signature,
    )
    .map_err(|_| "root-status-signature-invalid")
}

fn validate_stored_revocation(
    root: &policy_v3_root::Model,
    root_cid: &str,
    node_did: &str,
    now: OffsetDateTime,
) -> Result<(), &'static str> {
    let revocation_bytes = root
        .revocation_bytes
        .as_deref()
        .ok_or("root-revocation-bytes-missing")?;
    let revocation: Value =
        serde_json::from_slice(revocation_bytes).map_err(|_| "root-revocation-invalid")?;
    if canonical_json_value(&revocation) != revocation_bytes {
        return Err("root-revocation-not-canonical");
    }
    let root_event = decode_delegation(
        std::str::from_utf8(&root.authorization_bytes).map_err(|_| "policy-root-invalid")?,
    )
    .map_err(|_| "policy-root-invalid")?;
    let owner = fact(&root_event.0.delegation, "ownerDid").ok_or("policy-root-owner-missing")?;
    let (_, digest, revoked_at) = validate_root_revocation(
        &revocation,
        root_cid,
        &root.role,
        owner,
        fact(&root_event.0.delegation, "enforcerDid"),
        node_did,
        now,
    )
    .map_err(|_| "root-revocation-invalid")?;
    if root.revoked_at.as_deref() != Some(format_time(revoked_at).as_str()) {
        return Err("root-revocation-projection-mismatch");
    }
    let checkpoint_bytes = root
        .status_checkpoint_bytes
        .as_deref()
        .ok_or("root-status-missing")?;
    let checkpoint: Value =
        serde_json::from_slice(checkpoint_bytes).map_err(|_| "root-status-invalid")?;
    if canonical_json_value(&checkpoint) != checkpoint_bytes
        || checkpoint.get("state").and_then(Value::as_str) != Some("revoked")
        || checkpoint.get("targetCid").and_then(Value::as_str) != Some(root_cid)
        || checkpoint.get("targetRole").and_then(Value::as_str) != Some(root.role.as_str())
        || checkpoint.get("sequence").and_then(Value::as_i64) != Some(root.status_sequence)
        || checkpoint.get("revocationCid").and_then(Value::as_str) != Some(digest.as_str())
        || checkpoint.get("revokedAt").and_then(Value::as_str) != root.revoked_at.as_deref()
    {
        return Err("root-status-projection-mismatch");
    }
    verify_signed_json(&checkpoint, STATUS_DOMAIN, node_did)
        .map_err(|_| "root-status-signature-invalid")?;
    Ok(())
}

fn initial_status_checkpoint(
    runtime: &PolicyV3Runtime,
    root_cid: &str,
    role: &str,
    root: &TinyCloudDelegation,
    now: OffsetDateTime,
) -> Result<Vec<u8>, (Status, String)> {
    let checked_at = format_time(now);
    let fresh_until = format_time(now + Duration::seconds(MAX_STATUS_AGE_SECONDS));
    let mut unsigned = serde_json::json!({
        "schema": ROOT_STATUS_V1_SCHEMA,
        "targetCid": root_cid,
        "targetRole": role,
        "ownerDid": fact(root, "ownerDid").ok_or((Status::Forbidden, "root-owner-missing".into()))?,
        "nodeAudience": runtime.node_did.clone(),
        "state": "active",
        "sequence": 1,
        "checkedAt": checked_at,
        "freshUntil": fresh_until,
        "issuerDid": runtime.node_did.clone(),
    });
    let mut signed = STATUS_DOMAIN.to_vec();
    signed.extend_from_slice(&canonical_json_value(&unsigned));
    let signature = runtime
        .signer
        .node_keypair()
        .sign(&Sha256::digest(signed))
        .map_err(|error| (Status::InternalServerError, error.to_string()))?;
    unsigned["signature"] = serde_json::json!({
        "suite": "Ed25519",
        "signerDid": runtime.node_did.clone(),
        "value": base64::encode_config(signature, URL_SAFE_NO_PAD),
    });
    Ok(canonical_json_value(&unsigned))
}

fn checkpoint_predecessor_digest(bytes: &[u8]) -> Result<String, ()> {
    let mut value: Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    value.as_object_mut().ok_or(())?.remove("signature");
    let mut signed = STATUS_DOMAIN.to_vec();
    signed.extend_from_slice(&canonical_json_value(&value));
    Ok(hex::encode(Sha256::digest(signed)))
}

#[allow(dead_code)]
async fn ingest_status_checkpoint_unmounted(
    request: Json<StatusRequest>,
    runtime: &State<PolicyV3Runtime>,
) -> Result<Json<StatusResponse>, (Status, String)> {
    let request = request.into_inner();
    let root = policy_v3_root::Entity::find_by_id(request.root_cid.clone())
        .one(&runtime.conn)
        .await
        .map_err(db_error)?
        .ok_or((Status::NotFound, "policy-root-missing".into()))?;
    if root.revoked_at.is_some() || root.revocation_bytes.is_some() {
        return Err((Status::Conflict, "status-rollback".into()));
    }
    validate_persisted_root(
        &root,
        &request.root_cid,
        &root.policy_cid,
        &runtime.node_did,
    )
    .await
    .map_err(|error| (Status::Forbidden, error.to_string()))?;
    if canonical_json_value(&request.checkpoint)
        != serde_json::to_vec(&request.checkpoint)
            .map_err(|_| (Status::BadRequest, "status-invalid".into()))?
    {
        return Err((Status::Forbidden, "status-not-canonical".into()));
    }
    let object = request
        .checkpoint
        .as_object()
        .ok_or((Status::BadRequest, "status-invalid".into()))?;
    const STATUS_KEYS: &[&str] = &[
        "schema",
        "targetCid",
        "targetRole",
        "ownerDid",
        "nodeAudience",
        "state",
        "sequence",
        "checkedAt",
        "freshUntil",
        "revokedAt",
        "revocationCid",
        "previousCheckpointDigestHex",
        "issuerDid",
        "signature",
    ];
    if object
        .keys()
        .any(|key| !STATUS_KEYS.contains(&key.as_str()))
    {
        return Err((Status::BadRequest, "status-unknown-field".into()));
    }
    let root_delegation = decode_delegation(
        std::str::from_utf8(&root.authorization_bytes)
            .map_err(|_| (Status::Forbidden, "root-invalid".into()))?,
    )?;
    if object.get("schema").and_then(Value::as_str) != Some(ROOT_STATUS_V1_SCHEMA)
        || object.get("issuerDid").and_then(Value::as_str) != Some(runtime.node_did.as_str())
        || object.get("targetCid").and_then(Value::as_str) != Some(request.root_cid.as_str())
        || object.get("targetRole").and_then(Value::as_str) != Some(root.role.as_str())
        || object.get("ownerDid").and_then(Value::as_str)
            != Some(root_delegation.0.delegator.as_str())
        || object.get("nodeAudience").and_then(Value::as_str) != Some(runtime.node_did.as_str())
    {
        return Err((Status::Forbidden, "status-invalid".into()));
    }
    let sequence = object
        .get("sequence")
        .and_then(Value::as_i64)
        .ok_or((Status::BadRequest, "status-invalid".into()))?;
    if sequence != root.status_sequence + 1 {
        return Err((Status::Conflict, "status-rollback".into()));
    }
    let previous_digest = object
        .get("previousCheckpointDigestHex")
        .and_then(Value::as_str);
    if root.status_sequence == 0 {
        if previous_digest.is_some() {
            return Err((Status::Conflict, "status-chain-invalid".into()));
        }
    } else {
        let expected_previous = root
            .status_checkpoint_bytes
            .as_ref()
            .and_then(|bytes| checkpoint_predecessor_digest(bytes).ok());
        if previous_digest != expected_previous.as_deref() {
            return Err((Status::Conflict, "status-chain-invalid".into()));
        }
    }
    let checked = object
        .get("checkedAt")
        .and_then(Value::as_str)
        .ok_or((Status::BadRequest, "status-invalid".into()))?;
    let fresh = object
        .get("freshUntil")
        .and_then(Value::as_str)
        .ok_or((Status::BadRequest, "status-invalid".into()))?;
    let now = OffsetDateTime::now_utc();
    let checked_at = parse_time(checked).map_err(bad)?;
    let fresh_until = parse_time(fresh).map_err(bad)?;
    if checked_at > now
        || fresh_until <= now
        || fresh_until - checked_at > Duration::seconds(MAX_STATUS_AGE_SECONDS)
    {
        return Err((Status::Forbidden, "status-stale".into()));
    }
    let mut unsigned = request.checkpoint.clone();
    unsigned.as_object_mut().unwrap().remove("signature");
    let mut signed = STATUS_DOMAIN.to_vec();
    signed.extend_from_slice(&canonical_json_value(&unsigned));
    let signature = object
        .get("signature")
        .and_then(Value::as_object)
        .and_then(|s| s.get("value"))
        .and_then(Value::as_str)
        .ok_or((Status::Forbidden, "status-signature-missing".into()))?;
    if object
        .get("signature")
        .and_then(Value::as_object)
        .and_then(|s| s.get("signerDid"))
        .and_then(Value::as_str)
        != Some(runtime.node_did.as_str())
    {
        return Err((Status::Forbidden, "status-signature-invalid".into()));
    }
    if object
        .get("signature")
        .and_then(Value::as_object)
        .and_then(|s| s.get("suite"))
        .and_then(Value::as_str)
        != Some("Ed25519")
    {
        return Err((Status::Forbidden, "status-signature-invalid".into()));
    }
    let signature = decode_config(signature, URL_SAFE_NO_PAD)
        .map_err(|_| (Status::Forbidden, "status-signature-invalid".into()))?;
    let signed_digest = Sha256::digest(signed);
    tinycloud_auth::share_email_evidence::verify_detached_ed25519(
        &runtime.node_did,
        &signed_digest,
        &signature,
    )
    .map_err(|_| (Status::Forbidden, "status-signature-invalid".into()))?;
    let state = object
        .get("state")
        .and_then(Value::as_str)
        .ok_or((Status::BadRequest, "status-state-invalid".into()))?
        .to_owned();
    if root.revoked_at.is_some() && state != "revoked" {
        return Err((Status::Conflict, "status-rollback".into()));
    }
    let revoked_at = object
        .get("revokedAt")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if state != "active" && state != "revoked" {
        return Err((Status::BadRequest, "status-state-invalid".into()));
    }
    let revocation_bytes = if state == "revoked" {
        let revocation = request
            .revocation
            .as_ref()
            .and_then(Value::as_object)
            .ok_or((Status::Forbidden, "root-revocation-missing".into()))?;
        const REVOCATION_KEYS: &[&str] = &[
            "schema",
            "targetCid",
            "targetRole",
            "ownerDid",
            "nodeAudience",
            "revokedAt",
            "reason",
            "issuerDid",
            "signature",
        ];
        if revocation
            .keys()
            .any(|key| !REVOCATION_KEYS.contains(&key.as_str()))
        {
            return Err((Status::Forbidden, "root-revocation-unknown-field".into()));
        }
        if canonical_json_value(request.revocation.as_ref().unwrap())
            != serde_json::to_vec(request.revocation.as_ref().unwrap())
                .map_err(|_| (Status::Forbidden, "root-revocation-invalid".into()))?
        {
            return Err((Status::Forbidden, "root-revocation-invalid".into()));
        }
        if revocation.get("schema").and_then(Value::as_str) != Some(ROOT_REVOCATION_V1_SCHEMA)
            || revocation.get("targetCid").and_then(Value::as_str)
                != Some(request.root_cid.as_str())
            || revocation.get("targetRole").and_then(Value::as_str) != Some(root.role.as_str())
            || revocation.get("ownerDid").and_then(Value::as_str)
                != Some(root_delegation.0.delegator.as_str())
            || revocation.get("nodeAudience").and_then(Value::as_str)
                != Some(runtime.node_did.as_str())
            || revocation.get("revokedAt").and_then(Value::as_str) != revoked_at.as_deref()
            || revocation.get("reason").and_then(Value::as_str).is_none()
        {
            return Err((Status::Forbidden, "root-revocation-invalid".into()));
        }
        let mut unsigned = request.revocation.as_ref().unwrap().clone();
        let signature = unsigned
            .as_object_mut()
            .and_then(|object| object.remove("signature"))
            .and_then(|value| value.as_object().cloned())
            .ok_or((
                Status::Forbidden,
                "root-revocation-signature-missing".into(),
            ))?;
        let signer = signature.get("signerDid").and_then(Value::as_str).ok_or((
            Status::Forbidden,
            "root-revocation-signature-invalid".into(),
        ))?;
        let value = signature.get("value").and_then(Value::as_str).ok_or((
            Status::Forbidden,
            "root-revocation-signature-invalid".into(),
        ))?;
        let enforcer_did = match &root_delegation.0.delegation {
            TinyCloudDelegation::Ucan(ucan) => ucan
                .payload()
                .facts
                .as_ref()
                .and_then(|facts| facts.first())
                .and_then(Value::as_object)
                .and_then(|facts| facts.get("enforcerDid"))
                .and_then(Value::as_str),
            _ => None,
        };
        if signer != root_delegation.0.delegator
            && !(root.role == "policy-enforcement" && Some(signer) == enforcer_did)
        {
            return Err((
                Status::Forbidden,
                "root-revocation-signature-invalid".into(),
            ));
        }
        if revocation.get("issuerDid").and_then(Value::as_str) != Some(signer) {
            return Err((Status::Forbidden, "root-revocation-invalid".into()));
        }
        if signature.get("suite").and_then(Value::as_str) != Some("Ed25519") {
            return Err((
                Status::Forbidden,
                "root-revocation-signature-invalid".into(),
            ));
        }
        let mut signed = b"xyz.tinycloud.policy/RootRevocation/v1\0".to_vec();
        signed.extend_from_slice(&canonical_json_value(&unsigned));
        let revocation_digest = hex::encode(Sha256::digest(&signed));
        if object.get("revocationCid").and_then(Value::as_str) != Some(revocation_digest.as_str()) {
            return Err((Status::Forbidden, "root-revocation-digest-invalid".into()));
        }
        let signature = decode_config(value, URL_SAFE_NO_PAD).map_err(|_| {
            (
                Status::Forbidden,
                "root-revocation-signature-invalid".into(),
            )
        })?;
        let signed_digest = Sha256::digest(signed);
        tinycloud_auth::share_email_evidence::verify_detached_ed25519(
            signer,
            &signed_digest,
            &signature,
        )
        .map_err(|_| {
            (
                Status::Forbidden,
                "root-revocation-signature-invalid".into(),
            )
        })?;
        Some(canonical_json_value(request.revocation.as_ref().unwrap()))
    } else {
        if request.revocation.is_some() || revoked_at.is_some() {
            return Err((
                Status::Forbidden,
                "active-status-revocation-mismatch".into(),
            ));
        }
        None
    };
    let updated = policy_v3_root::Entity::update_many()
        .col_expr(
            policy_v3_root::Column::PreviousCheckpointDigestHex,
            Expr::value(
                root.status_checkpoint_bytes
                    .as_ref()
                    .and_then(|bytes| checkpoint_predecessor_digest(bytes).ok()),
            ),
        )
        .col_expr(
            policy_v3_root::Column::StatusCheckpointBytes,
            Expr::value(canonical_json_value(&request.checkpoint)),
        )
        .col_expr(
            policy_v3_root::Column::StatusSequence,
            Expr::value(sequence),
        )
        .col_expr(
            policy_v3_root::Column::StatusCheckedAt,
            Expr::value(checked.to_owned()),
        )
        .col_expr(
            policy_v3_root::Column::StatusFreshUntil,
            Expr::value(fresh.to_owned()),
        )
        .col_expr(policy_v3_root::Column::RevokedAt, Expr::value(revoked_at))
        .col_expr(
            policy_v3_root::Column::RevocationBytes,
            Expr::value(revocation_bytes),
        )
        .filter(policy_v3_root::Column::RootCid.eq(request.root_cid.clone()))
        .filter(policy_v3_root::Column::StatusSequence.eq(root.status_sequence))
        .exec(&runtime.conn)
        .await
        .map_err(db_error)?;
    if updated.rows_affected != 1 {
        return Err((Status::Conflict, "status-concurrent-update".into()));
    }
    Ok(Json(StatusResponse {
        root_cid: request.root_cid,
        sequence,
        state,
    }))
}

#[post("/share/v3/policy/status", format = "json", data = "<request>")]
pub async fn status(
    request: Json<StatusRenewalRequest>,
    runtime: &State<PolicyV3Runtime>,
) -> Result<Json<StatusResponse>, (Status, String)> {
    let request = request.into_inner();
    let root = policy_v3_root::Entity::find_by_id(request.root_cid.clone())
        .one(&runtime.conn)
        .await
        .map_err(db_error)?
        .ok_or((Status::NotFound, "policy-root-missing".into()))?;
    if root.revoked_at.is_some() || root.revocation_bytes.is_some() {
        return Err((Status::Conflict, "root-revoked".into()));
    }
    validate_persisted_root(
        &root,
        &request.root_cid,
        &root.policy_cid,
        &runtime.node_did,
    )
    .await
    .map_err(|error| (Status::Forbidden, error.into()))?;
    let root_event = decode_delegation(
        std::str::from_utf8(&root.authorization_bytes)
            .map_err(|_| (Status::Forbidden, "policy-root-invalid".into()))?,
    )?;
    let owner = fact(&root_event.0.delegation, "ownerDid")
        .ok_or((Status::Forbidden, "policy-root-owner-missing".into()))?;
    let sequence = root.status_sequence + 1;
    let previous = root
        .status_checkpoint_bytes
        .as_deref()
        .and_then(|bytes| checkpoint_predecessor_digest(bytes).ok())
        .ok_or((Status::Conflict, "status-chain-invalid".into()))?;
    validate_status_renewal(
        &request.renewal,
        &request.root_cid,
        owner,
        &runtime.node_did,
        sequence,
        &previous,
        OffsetDateTime::now_utc(),
    )?;
    let now = OffsetDateTime::now_utc();
    let checkpoint = signed_status_checkpoint(
        runtime,
        &request.root_cid,
        &root.role,
        owner,
        "active",
        sequence,
        now,
        Some(previous.clone()),
        None,
        None,
    )?;
    let updated = policy_v3_root::Entity::update_many()
        .col_expr(
            policy_v3_root::Column::StatusCheckpointBytes,
            Expr::value(checkpoint),
        )
        .col_expr(
            policy_v3_root::Column::PreviousCheckpointDigestHex,
            Expr::value(previous),
        )
        .col_expr(
            policy_v3_root::Column::StatusSequence,
            Expr::value(sequence),
        )
        .col_expr(
            policy_v3_root::Column::StatusCheckedAt,
            Expr::value(format_time(now)),
        )
        .col_expr(
            policy_v3_root::Column::StatusFreshUntil,
            Expr::value(format_time(now + Duration::seconds(MAX_STATUS_AGE_SECONDS))),
        )
        .filter(policy_v3_root::Column::RootCid.eq(request.root_cid.clone()))
        .filter(policy_v3_root::Column::StatusSequence.eq(root.status_sequence))
        .filter(policy_v3_root::Column::RevokedAt.is_null())
        .exec(&runtime.conn)
        .await
        .map_err(db_error)?;
    if updated.rows_affected != 1 {
        return Err((Status::Conflict, "status-concurrent-update".into()));
    }
    Ok(Json(StatusResponse {
        root_cid: request.root_cid,
        sequence,
        state: "active".into(),
    }))
}

/// Return the exact current signed checkpoint so an owner can bind the next
/// renewal to its sequence and predecessor digest. The checkpoint is public
/// liveness evidence; it cannot grant or widen authority.
#[get("/share/v3/policy/status/<root_cid>")]
pub async fn get_status(
    root_cid: &str,
    runtime: &State<PolicyV3Runtime>,
) -> Result<Json<StatusCheckpointResponse>, (Status, String)> {
    let root = policy_v3_root::Entity::find_by_id(root_cid.to_owned())
        .one(&runtime.conn)
        .await
        .map_err(db_error)?
        .ok_or((Status::NotFound, "policy-root-missing".into()))?;
    if root.revoked_at.is_none() {
        validate_stored_root_status(
            &root,
            root_cid,
            &runtime.node_did,
            OffsetDateTime::now_utc(),
            false,
        )
        .map_err(|error| (Status::Forbidden, error.into()))?;
    } else {
        validate_stored_revocation(
            &root,
            root_cid,
            &runtime.node_did,
            OffsetDateTime::now_utc(),
        )
        .map_err(|error| (Status::Forbidden, error.into()))?;
    }
    let checkpoint: Value = serde_json::from_slice(
        root.status_checkpoint_bytes
            .as_deref()
            .ok_or((Status::Forbidden, "root-status-missing".into()))?,
    )
    .map_err(|_| (Status::Forbidden, "root-status-invalid".into()))?;
    let revocation = root
        .revocation_bytes
        .as_deref()
        .map(serde_json::from_slice)
        .transpose()
        .map_err(|_| (Status::Forbidden, "root-revocation-invalid".into()))?;
    Ok(Json(StatusCheckpointResponse {
        root_cid: root_cid.to_owned(),
        state: if root.revoked_at.is_some() {
            "revoked"
        } else {
            "active"
        }
        .into(),
        checkpoint,
        revocation,
    }))
}

#[post("/revoke", rank = 1, format = "json", data = "<request>")]
pub async fn revoke_root(
    request: Json<RootRevocationRequest>,
    runtime: &State<PolicyV3Runtime>,
) -> Result<Json<crate::routes::RevokeResponse>, (Status, String)> {
    let request = request.into_inner();
    let object = request
        .revocation
        .as_object()
        .ok_or((Status::BadRequest, "root-revocation-invalid".into()))?;
    let root_cid = object
        .get("targetCid")
        .and_then(Value::as_str)
        .ok_or((Status::BadRequest, "root-revocation-target-missing".into()))?
        .to_owned();
    let root = policy_v3_root::Entity::find_by_id(root_cid.clone())
        .one(&runtime.conn)
        .await
        .map_err(db_error)?
        .ok_or((Status::NotFound, "policy-root-missing".into()))?;
    if let Some(existing) = root.revocation_bytes.as_deref() {
        if existing == canonical_json_value(&request.revocation) {
            return Ok(Json(crate::routes::RevokeResponse {
                revoked: true,
                cid: root_cid,
            }));
        }
        return Err((Status::Conflict, "root-revocation-irreversible".into()));
    }
    validate_persisted_root(&root, &root_cid, &root.policy_cid, &runtime.node_did)
        .await
        .map_err(|error| (Status::Forbidden, error.into()))?;
    let root_event = decode_delegation(
        std::str::from_utf8(&root.authorization_bytes)
            .map_err(|_| (Status::Forbidden, "policy-root-invalid".into()))?,
    )?;
    let owner = fact(&root_event.0.delegation, "ownerDid")
        .ok_or((Status::Forbidden, "policy-root-owner-missing".into()))?;
    let (revocation_bytes, revocation_digest, revoked_at) = validate_root_revocation(
        &request.revocation,
        &root_cid,
        &root.role,
        owner,
        fact(&root_event.0.delegation, "enforcerDid"),
        &runtime.node_did,
        OffsetDateTime::now_utc(),
    )?;
    let previous = root
        .status_checkpoint_bytes
        .as_deref()
        .and_then(|bytes| checkpoint_predecessor_digest(bytes).ok())
        .ok_or((Status::Conflict, "status-chain-invalid".into()))?;
    let sequence = root.status_sequence + 1;
    let checkpoint = signed_status_checkpoint(
        runtime,
        &root_cid,
        &root.role,
        owner,
        "revoked",
        sequence,
        OffsetDateTime::now_utc(),
        Some(previous.clone()),
        Some(format_time(revoked_at)),
        Some(revocation_digest),
    )?;
    let updated = policy_v3_root::Entity::update_many()
        .col_expr(
            policy_v3_root::Column::StatusCheckpointBytes,
            Expr::value(checkpoint),
        )
        .col_expr(
            policy_v3_root::Column::PreviousCheckpointDigestHex,
            Expr::value(previous),
        )
        .col_expr(
            policy_v3_root::Column::StatusSequence,
            Expr::value(sequence),
        )
        .col_expr(
            policy_v3_root::Column::StatusCheckedAt,
            Expr::value(format_time(OffsetDateTime::now_utc())),
        )
        .col_expr(
            policy_v3_root::Column::StatusFreshUntil,
            Expr::value(format_time(
                OffsetDateTime::now_utc() + Duration::seconds(MAX_STATUS_AGE_SECONDS),
            )),
        )
        .col_expr(
            policy_v3_root::Column::RevokedAt,
            Expr::value(format_time(revoked_at)),
        )
        .col_expr(
            policy_v3_root::Column::RevocationBytes,
            Expr::value(revocation_bytes),
        )
        .filter(policy_v3_root::Column::RootCid.eq(root_cid.clone()))
        .filter(policy_v3_root::Column::StatusSequence.eq(root.status_sequence))
        .filter(policy_v3_root::Column::RevokedAt.is_null())
        .exec(&runtime.conn)
        .await
        .map_err(db_error)?;
    if updated.rows_affected != 1 {
        return Err((Status::Conflict, "root-revocation-concurrent".into()));
    }
    Ok(Json(crate::routes::RevokeResponse {
        revoked: true,
        cid: root_cid,
    }))
}

fn validate_status_renewal(
    value: &Value,
    root_cid: &str,
    owner: &str,
    node_did: &str,
    sequence: i64,
    previous: &str,
    now: OffsetDateTime,
) -> Result<(), (Status, String)> {
    let object = value
        .as_object()
        .ok_or((Status::BadRequest, "status-renewal-invalid".into()))?;
    const KEYS: &[&str] = &[
        "schema",
        "targetCid",
        "ownerDid",
        "nodeAudience",
        "issuedAt",
        "nonce",
        "sequence",
        "previousCheckpointDigestHex",
        "signature",
    ];
    if object.len() != KEYS.len()
        || object.keys().any(|key| !KEYS.contains(&key.as_str()))
        || object.get("schema").and_then(Value::as_str)
            != Some("xyz.tinycloud.policy/root-status-renewal/v1")
        || object.get("targetCid").and_then(Value::as_str) != Some(root_cid)
        || object.get("ownerDid").and_then(Value::as_str) != Some(owner)
        || object.get("nodeAudience").and_then(Value::as_str) != Some(node_did)
        || object.get("sequence").and_then(Value::as_i64) != Some(sequence)
        || object
            .get("previousCheckpointDigestHex")
            .and_then(Value::as_str)
            != Some(previous)
        || object
            .get("nonce")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err((Status::Forbidden, "status-renewal-invalid".into()));
    }
    let issued = object
        .get("issuedAt")
        .and_then(Value::as_str)
        .and_then(|value| parse_time(value).ok())
        .ok_or((Status::Forbidden, "status-renewal-time-invalid".into()))?;
    if issued > now || now - issued > Duration::seconds(60) {
        return Err((Status::Forbidden, "status-renewal-time-invalid".into()));
    }
    verify_signed_json(value, b"xyz.tinycloud.policy/RootStatusRenewal/v1\0", owner)
}

fn validate_root_revocation(
    value: &Value,
    root_cid: &str,
    role: &str,
    owner: &str,
    enforcer: Option<&str>,
    node_did: &str,
    now: OffsetDateTime,
) -> Result<(Vec<u8>, String, OffsetDateTime), (Status, String)> {
    let object = value
        .as_object()
        .ok_or((Status::BadRequest, "root-revocation-invalid".into()))?;
    const KEYS: &[&str] = &[
        "schema",
        "targetCid",
        "targetRole",
        "ownerDid",
        "nodeAudience",
        "revokedAt",
        "reason",
        "issuerDid",
        "signature",
    ];
    if object.len() != KEYS.len()
        || object.keys().any(|key| !KEYS.contains(&key.as_str()))
        || object.get("schema").and_then(Value::as_str) != Some(ROOT_REVOCATION_V1_SCHEMA)
        || object.get("targetCid").and_then(Value::as_str) != Some(root_cid)
        || object.get("targetRole").and_then(Value::as_str) != Some(role)
        || object.get("ownerDid").and_then(Value::as_str) != Some(owner)
        || object.get("nodeAudience").and_then(Value::as_str) != Some(node_did)
        || object
            .get("reason")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err((Status::Forbidden, "root-revocation-invalid".into()));
    }
    let issuer = object
        .get("issuerDid")
        .and_then(Value::as_str)
        .ok_or((Status::Forbidden, "root-revocation-issuer-invalid".into()))?;
    if issuer != owner && !(role == "policy-enforcement" && enforcer == Some(issuer)) {
        return Err((Status::Forbidden, "root-revocation-issuer-invalid".into()));
    }
    let revoked_at_text = object
        .get("revokedAt")
        .and_then(Value::as_str)
        .ok_or((Status::Forbidden, "root-revocation-time-invalid".into()))?;
    let revoked_at = parse_time(revoked_at_text)
        .map_err(|_| (Status::Forbidden, "root-revocation-time-invalid".into()))?;
    if format_time(revoked_at) != revoked_at_text || revoked_at > now + Duration::seconds(60) {
        return Err((Status::Forbidden, "root-revocation-time-invalid".into()));
    }
    verify_signed_json(value, b"xyz.tinycloud.policy/RootRevocation/v1\0", issuer)?;
    let mut unsigned = value.clone();
    unsigned.as_object_mut().unwrap().remove("signature");
    let mut preimage = b"xyz.tinycloud.policy/RootRevocation/v1\0".to_vec();
    preimage.extend_from_slice(&canonical_json_value(&unsigned));
    Ok((
        canonical_json_value(value),
        hex::encode(Sha256::digest(preimage)),
        revoked_at,
    ))
}

fn verify_signed_json(
    value: &Value,
    domain: &[u8],
    expected_signer: &str,
) -> Result<(), (Status, String)> {
    let mut unsigned = value.clone();
    let signature = unsigned
        .as_object_mut()
        .and_then(|object| object.remove("signature"))
        .and_then(|value| value.as_object().cloned())
        .ok_or((Status::Forbidden, "signature-missing".into()))?;
    if signature.len() != 3
        || signature.get("suite").and_then(Value::as_str) != Some("Ed25519")
        || signature.get("signerDid").and_then(Value::as_str) != Some(expected_signer)
    {
        return Err((Status::Forbidden, "signature-invalid".into()));
    }
    let signature = signature
        .get("value")
        .and_then(Value::as_str)
        .and_then(|value| decode_config(value, URL_SAFE_NO_PAD).ok())
        .filter(|bytes| bytes.len() == 64)
        .ok_or((Status::Forbidden, "signature-invalid".into()))?;
    let mut signed = domain.to_vec();
    signed.extend_from_slice(&canonical_json_value(&unsigned));
    tinycloud_auth::share_email_evidence::verify_detached_ed25519(
        expected_signer,
        &Sha256::digest(signed),
        &signature,
    )
    .map_err(|_| (Status::Forbidden, "signature-invalid".into()))
}

#[allow(clippy::too_many_arguments)]
fn signed_status_checkpoint(
    runtime: &PolicyV3Runtime,
    root_cid: &str,
    role: &str,
    owner: &str,
    state: &str,
    sequence: i64,
    now: OffsetDateTime,
    previous: Option<String>,
    revoked_at: Option<String>,
    revocation_cid: Option<String>,
) -> Result<Vec<u8>, (Status, String)> {
    let mut object = serde_json::json!({
        "schema": ROOT_STATUS_V1_SCHEMA,
        "targetCid": root_cid,
        "targetRole": role,
        "ownerDid": owner,
        "nodeAudience": runtime.node_did,
        "state": state,
        "sequence": sequence,
        "checkedAt": format_time(now),
        "freshUntil": format_time(now + Duration::seconds(MAX_STATUS_AGE_SECONDS)),
        "issuerDid": runtime.node_did,
    });
    if let Some(previous) = previous {
        object["previousCheckpointDigestHex"] = Value::String(previous);
    }
    if let Some(revoked_at) = revoked_at {
        object["revokedAt"] = Value::String(revoked_at);
    }
    if let Some(revocation_cid) = revocation_cid {
        object["revocationCid"] = Value::String(revocation_cid);
    }
    let mut signed = STATUS_DOMAIN.to_vec();
    signed.extend_from_slice(&canonical_json_value(&object));
    let signature = runtime
        .signer
        .node_keypair()
        .sign(&Sha256::digest(signed))
        .map_err(|error| (Status::InternalServerError, error.to_string()))?;
    object["signature"] = serde_json::json!({
        "suite": "Ed25519",
        "signerDid": runtime.node_did,
        "value": base64::encode_config(signature, URL_SAFE_NO_PAD),
    });
    Ok(canonical_json_value(&object))
}

pub fn is_policy_session(delegation: &DelegationInfo) -> bool {
    let TinyCloudDelegation::Ucan(ucan) = &delegation.delegation else {
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
    object.len() == REQUIRED_FACTS.len()
        && object.get("profile").and_then(Value::as_str) == Some(POLICY_SESSION_PROFILE)
        && object
            .keys()
            .all(|key| REQUIRED_FACTS.contains(&key.as_str()))
        && REQUIRED_FACTS
            .iter()
            .filter(|key| **key != "remainingRedelegationDepth")
            .all(|key| {
                object
                    .get(*key)
                    .and_then(Value::as_str)
                    .is_some_and(|v| !v.is_empty())
            })
        && object
            .get("remainingRedelegationDepth")
            .and_then(Value::as_u64)
            .is_some_and(|depth| depth <= 8)
}

fn descendant_profile_is_inherited(child: &DelegationInfo, parent: &DelegationInfo) -> bool {
    const INHERITED_FACTS: &[&str] = &[
        "profile",
        "policyCid",
        "policyDelegationCid",
        "enforcementDelegationCid",
        "enforcerDid",
        "nodeAudience",
        "recipientDid",
        "ownerDid",
        "policyId",
        "policyDigestHex",
        "contentSourceDigestHex",
        "capabilityCeilingHashHex",
        "nativeProjectionHashHex",
        "challengeId",
        "claimDigestHex",
        "claimJti",
        "vpDigestHex",
        "credentialEvidenceDigestHex",
        "decisionContextDigestHex",
        "issuanceAuditDigestHex",
    ];
    INHERITED_FACTS
        .iter()
        .all(|key| fact(&child.delegation, key) == fact(&parent.delegation, key))
        && profile_depth(&child.delegation)
            .zip(profile_depth(&parent.delegation))
            .is_some_and(|(child_depth, parent_depth)| {
                parent_depth > 0 && child_depth == parent_depth - 1
            })
}

fn descendant_time_is_narrower(child: &DelegationInfo, parent: &DelegationInfo) -> bool {
    let not_before_ok = match (child.not_before, parent.not_before) {
        (Some(child), Some(parent)) => child > parent,
        (None, Some(_)) => false,
        _ => true,
    };
    let expiry_ok = match (child.expiry, parent.expiry) {
        (Some(child), Some(parent)) => child < parent,
        _ => false,
    };
    not_before_ok && expiry_ok
}

fn profile_depth(delegation: &TinyCloudDelegation) -> Option<u64> {
    let TinyCloudDelegation::Ucan(ucan) = delegation else {
        return None;
    };
    ucan.payload().facts.as_ref()?.iter().find_map(|value| {
        value
            .as_object()?
            .get("remainingRedelegationDepth")
            .and_then(Value::as_u64)
    })
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
    let Some(role) = object.get("role").and_then(Value::as_str) else {
        return false;
    };
    let required = [
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
    let enforcement_only = ["enforcerDid"];
    let allowed = if role == "policy-enforcement" {
        required
            .iter()
            .chain(enforcement_only.iter())
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
    } else if role == "policy-authority" {
        required
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
    } else {
        return false;
    };
    object.len() == allowed.len()
        && object.keys().all(|key| allowed.contains(key.as_str()))
        && object.get("mode").and_then(Value::as_str)
            == Some(if role == "policy-authority" {
                "policy-source"
            } else {
                "conditional-mint"
            })
        && allowed.iter().all(|key| {
            object
                .get(*key)
                .and_then(Value::as_str)
                .is_some_and(|v| !v.is_empty())
        })
}

fn fact<'a>(delegation: &'a TinyCloudDelegation, key: &str) -> Option<&'a str> {
    let TinyCloudDelegation::Ucan(ucan) = delegation else {
        return None;
    };
    ucan.payload().facts.as_ref()?.iter().find_map(|value| {
        let object = value.as_object()?;
        let prefixed = format!("xyz.tinycloud.policy/{key}");
        object
            .get(key)
            .or_else(|| object.get(&prefixed))
            .and_then(Value::as_str)
    })
}

fn validate_policy_document(
    policy: &Value,
    canonical_bytes: &[u8],
    policy_cid: &str,
) -> Result<(), (Status, String)> {
    let object = policy
        .as_object()
        .ok_or((Status::BadRequest, "policy-invalid".into()))?;
    const POLICY_V1_KEYS: &[&str] = &[
        "schema",
        "policyId",
        "ownerDid",
        "createdAt",
        "expiresAt",
        "contentSource",
        "capabilityCeiling",
        "signature",
    ];
    const POLICY_V2_KEYS: &[&str] = &[
        "schema",
        "policyId",
        "ownerDid",
        "createdAt",
        "expiresAt",
        "contentSource",
        "capabilityCeiling",
        "credentialRequirement",
        "signature",
    ];
    let schema = object
        .get("schema")
        .and_then(Value::as_str)
        .ok_or((Status::BadRequest, "policy-invalid".into()))?;
    let expected_keys = match schema {
        POLICY_V1_SCHEMA => POLICY_V1_KEYS,
        POLICY_V2_SCHEMA => POLICY_V2_KEYS,
        _ => return Err((Status::BadRequest, "policy-schema-unsupported".into())),
    };
    if object
        .keys()
        .any(|key| !expected_keys.contains(&key.as_str()))
        || (schema == POLICY_V2_SCHEMA
            && (object.len() < expected_keys.len() - 1 || object.len() > expected_keys.len()))
    {
        return Err((Status::BadRequest, "policy-unknown-field".into()));
    }
    if object.get("policyId").and_then(Value::as_str).is_none()
        || object.get("ownerDid").and_then(Value::as_str).is_none()
        || object.get("createdAt").and_then(Value::as_str).is_none()
        || object
            .get("contentSource")
            .and_then(Value::as_object)
            .is_none()
        || object
            .get("capabilityCeiling")
            .and_then(Value::as_array)
            .is_none()
        || object.get("signature").and_then(Value::as_object).is_none()
    {
        return Err((Status::BadRequest, "policy-invalid".into()));
    }
    if schema == POLICY_V2_SCHEMA {
        validate_policy_credential_requirement(
            object
                .get("credentialRequirement")
                .ok_or((Status::BadRequest, "credential-requirement-missing".into()))?,
        )?;
    }
    let created_text = object.get("createdAt").and_then(Value::as_str).unwrap();
    let created =
        parse_time(created_text).map_err(|_| (Status::BadRequest, "policy-time-invalid".into()))?;
    if format_time(created) != created_text || created > OffsetDateTime::now_utc() {
        return Err((Status::BadRequest, "policy-time-invalid".into()));
    }
    if let Some(expires_text) = object.get("expiresAt").and_then(Value::as_str) {
        let expires = parse_time(expires_text)
            .map_err(|_| (Status::BadRequest, "policy-time-invalid".into()))?;
        if format_time(expires) != expires_text
            || expires <= created
            || expires <= OffsetDateTime::now_utc()
        {
            return Err((Status::BadRequest, "policy-time-invalid".into()));
        }
    }
    let expected = tinycloud_auth::ipld_core::cid::Cid::new_v1(
        0x55,
        tinycloud_auth::multihash_codetable::Code::Sha2_256.digest(canonical_bytes),
    )
    .to_string();
    if expected != policy_cid {
        return Err((Status::Forbidden, "policy-cid-mismatch".into()));
    }
    let signature = object
        .get("signature")
        .and_then(Value::as_object)
        .ok_or((Status::BadRequest, "policy-invalid".into()))?;
    if signature.len() != 3
        || signature
            .keys()
            .any(|key| !["suite", "signerDid", "value"].contains(&key.as_str()))
        || signature.get("suite").and_then(Value::as_str) != Some("Ed25519")
        || signature.get("signerDid").and_then(Value::as_str)
            != object.get("ownerDid").and_then(Value::as_str)
    {
        return Err((Status::Forbidden, "policy-signature-invalid".into()));
    }
    let signature_value = signature
        .get("value")
        .and_then(Value::as_str)
        .ok_or((Status::Forbidden, "policy-signature-invalid".into()))?;
    let signature = decode_config(signature_value, URL_SAFE_NO_PAD)
        .map_err(|_| (Status::Forbidden, "policy-signature-invalid".into()))?;
    if signature.len() != 64 {
        return Err((Status::Forbidden, "policy-signature-invalid".into()));
    }
    let mut unsigned = policy.clone();
    let unsigned_object = unsigned
        .as_object_mut()
        .ok_or((Status::BadRequest, "policy-invalid".into()))?;
    unsigned_object.remove("policyId");
    unsigned_object.remove("signature");
    let mut signing_bytes = schema.as_bytes().to_vec();
    signing_bytes.extend_from_slice(b"\0");
    signing_bytes.extend_from_slice(&canonical_json_value(&unsigned));
    let digest = Sha256::digest(signing_bytes);
    tinycloud_auth::share_email_evidence::verify_detached_ed25519(
        object
            .get("ownerDid")
            .and_then(Value::as_str)
            .ok_or((Status::BadRequest, "policy-invalid".into()))?,
        &digest,
        &signature,
    )
    .map_err(|_| (Status::Forbidden, "policy-signature-invalid".into()))?;
    let policy_digest = Sha256::digest({
        let mut unsigned_without_id = policy.clone();
        let unsigned_object = unsigned_without_id
            .as_object_mut()
            .ok_or((Status::BadRequest, "policy-invalid".into()))?;
        unsigned_object.remove("policyId");
        unsigned_object.remove("signature");
        let mut preimage = schema.as_bytes().to_vec();
        preimage.push(0);
        preimage.extend_from_slice(&canonical_json_value(&unsigned_without_id));
        preimage
    });
    let expected_policy_id = format!("pol_{}", base32_lower(&policy_digest));
    if object.get("policyId").and_then(Value::as_str) != Some(expected_policy_id.as_str()) {
        return Err((Status::Forbidden, "policy-id-mismatch".into()));
    }
    Ok(())
}

fn validate_policy_credential_requirement(
    value: &Value,
) -> Result<&serde_json::Map<String, Value>, (Status, String)> {
    let object = value
        .as_object()
        .ok_or((Status::BadRequest, "credential-requirement-invalid".into()))?;
    const KEYS: &[&str] = &[
        "type",
        "version",
        "requirementDigest",
        "descriptorDigest",
        "issuerDid",
        "issuerKid",
        "profile",
        "credentialType",
    ];
    if object.len() != KEYS.len()
        || object.keys().any(|key| !KEYS.contains(&key.as_str()))
        || object.get("type").and_then(Value::as_str) != Some(POLICY_CREDENTIAL_REQUIREMENT_V1)
        || object.get("version").and_then(Value::as_u64) != Some(1)
        || !object
            .get("requirementDigest")
            .and_then(Value::as_str)
            .is_some_and(is_base64url_digest)
        || !object
            .get("descriptorDigest")
            .and_then(Value::as_str)
            .is_some_and(is_base64url_digest)
        || object
            .get("issuerDid")
            .and_then(Value::as_str)
            .is_none_or(|value| !value.starts_with("did:"))
        || object
            .get("issuerKid")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || !versioned_identifier(object.get("profile"))
        || !versioned_identifier(object.get("credentialType"))
    {
        return Err((Status::BadRequest, "credential-requirement-invalid".into()));
    }
    Ok(object)
}

fn versioned_identifier(value: Option<&Value>) -> bool {
    value.and_then(Value::as_object).is_some_and(|object| {
        object.len() == 2
            && object.get("version").and_then(Value::as_u64) == Some(1)
            && object.get("id").and_then(Value::as_str).is_some_and(|id| {
                id.len() <= 131
                    && id
                        .bytes()
                        .next()
                        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                    && id.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'.' | b'_' | b'-' | b'/')
                    })
            })
    })
}

fn is_base64url_digest(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn canonical_digest_base64url(value: &Value) -> String {
    base64::encode_config(Sha256::digest(canonical_json_value(value)), URL_SAFE_NO_PAD)
}

fn decode_root(
    value: &str,
) -> Result<(String, tinycloud_core::events::Delegation), (Status, String)> {
    let event = decode_delegation(value)?;
    if !event.0.parents.is_empty() {
        return Err((Status::Forbidden, "root-must-not-have-proofs".into()));
    }
    Ok((event.content_hash().to_cid(0x55).to_string(), event))
}

fn decode_delegation(value: &str) -> Result<tinycloud_core::events::Delegation, (Status, String)> {
    SerializedEvent::<DelegationInfo>::from_header_ser::<TinyCloudDelegation>(value)
        .map_err(|e| (Status::BadRequest, e.to_string()))
}

async fn verify_signed_delegation(delegation: &TinyCloudDelegation) -> Result<(), ()> {
    let TinyCloudDelegation::Ucan(ucan) = delegation else {
        return Err(());
    };
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        ucan.verify_signature(&AnyDidMethod::default()),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    ucan.payload().validate_time(None).map_err(|_| ())
}

struct RegistrationProjections {
    content_source_digest_hex: String,
    capability_ceiling_hash_hex: String,
    native_projection_hash_hex: String,
    attenuation: Value,
}

fn registration_projections(policy: &Value) -> Result<RegistrationProjections, (Status, String)> {
    let object = policy
        .as_object()
        .ok_or((Status::BadRequest, "policy-invalid".into()))?;
    let source = object
        .get("contentSource")
        .and_then(Value::as_object)
        .ok_or((Status::BadRequest, "content-source-invalid".into()))?;
    const SOURCE_KEYS: &[&str] = &[
        "shareId",
        "kvResource",
        "selector",
        "encryptionNetwork",
        "encryptedSymmetricKeyDigestHex",
        "keyVersion",
        "mode",
        "initialCiphertextDigestHex",
    ];
    if source
        .keys()
        .any(|key| !SOURCE_KEYS.contains(&key.as_str()))
        || source
            .get("shareId")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || source
            .get("keyVersion")
            .and_then(Value::as_u64)
            .is_none_or(|v| v == 0)
        || !matches!(
            source.get("mode").and_then(Value::as_str),
            Some("mutable" | "immutable")
        )
        || source.get("mode").and_then(Value::as_str) == Some("immutable")
            && source.get("initialCiphertextDigestHex").is_none()
    {
        return Err((Status::BadRequest, "content-source-invalid".into()));
    }
    for key in [
        "encryptedSymmetricKeyDigestHex",
        "initialCiphertextDigestHex",
    ] {
        if let Some(value) = source.get(key) {
            if !value.as_str().is_some_and(is_lower_hex_digest) {
                return Err((Status::BadRequest, "content-source-digest-invalid".into()));
            }
        }
    }
    let kv_resource = source
        .get("kvResource")
        .and_then(Value::as_str)
        .ok_or((Status::BadRequest, "content-source-invalid".into()))?;
    let (source_space, source_path) = parse_policy_kv_resource(kv_resource)?;
    let selector = source
        .get("selector")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "exact" | "prefix"))
        .ok_or((Status::BadRequest, "content-source-invalid".into()))?;
    let encryption_network = source
        .get("encryptionNetwork")
        .and_then(Value::as_str)
        .ok_or((Status::BadRequest, "content-source-invalid".into()))?;
    validate_policy_encryption_resource(encryption_network)?;

    let capabilities = object
        .get("capabilityCeiling")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .ok_or((Status::BadRequest, "capability-ceiling-invalid".into()))?;
    let mut canonical_capabilities = Vec::new();
    let mut native = Vec::new();
    let mut attenuation = serde_json::Map::new();
    let mut saw_source_kv = false;
    let mut saw_source_encryption = false;
    for capability in capabilities {
        let cap = capability
            .as_object()
            .ok_or((Status::BadRequest, "capability-invalid".into()))?;
        match cap.get("kind").and_then(Value::as_str) {
            Some("kv") => {
                if cap.len() != 4
                    || cap.keys().any(|key| {
                        !["kind", "resource", "selector", "actions"].contains(&key.as_str())
                    })
                {
                    return Err((Status::BadRequest, "capability-invalid".into()));
                }
                let resource = cap
                    .get("resource")
                    .and_then(Value::as_str)
                    .ok_or((Status::BadRequest, "capability-invalid".into()))?;
                let (space, path) = parse_policy_kv_resource(resource)?;
                let kind = cap
                    .get("selector")
                    .and_then(Value::as_str)
                    .filter(|value| matches!(*value, "exact" | "prefix"))
                    .ok_or((Status::BadRequest, "capability-invalid".into()))?;
                let actions = canonical_policy_actions(cap.get("actions"), true)?;
                let caveat = serde_json::json!({
                    "kind": kind,
                    "type": "xyz.tinycloud.resource/selector",
                    "value": resource,
                });
                let mut abilities = serde_json::Map::new();
                for action in &actions {
                    abilities.insert(action.clone(), Value::Array(vec![caveat.clone()]));
                }
                if attenuation
                    .insert(resource.to_owned(), Value::Object(abilities))
                    .is_some()
                {
                    return Err((Status::BadRequest, "capability-duplicate".into()));
                }
                native.push(serde_json::json!({
                    "service": "tinycloud.kv",
                    "space": space,
                    "path": path,
                    "actions": actions,
                    "caveat": caveat,
                }));
                saw_source_kv |= resource == kv_resource
                    && kind == selector
                    && space == source_space
                    && path == source_path;
            }
            Some("encryption") => {
                if cap.len() != 3
                    || cap
                        .keys()
                        .any(|key| !["kind", "resource", "action"].contains(&key.as_str()))
                {
                    return Err((Status::BadRequest, "capability-invalid".into()));
                }
                let resource = cap
                    .get("resource")
                    .and_then(Value::as_str)
                    .ok_or((Status::BadRequest, "capability-invalid".into()))?;
                validate_policy_encryption_resource(resource)?;
                if cap.get("action").and_then(Value::as_str) != Some("tinycloud.encryption/decrypt")
                {
                    return Err((Status::BadRequest, "capability-invalid".into()));
                }
                if attenuation
                    .insert(
                        resource.to_owned(),
                        serde_json::json!({"tinycloud.encryption/decrypt": [{}]}),
                    )
                    .is_some()
                {
                    return Err((Status::BadRequest, "capability-duplicate".into()));
                }
                native.push(serde_json::json!({
                    "service": "tinycloud.encryption",
                    "space": resource,
                    "path": resource,
                    "actions": ["tinycloud.encryption/decrypt"],
                }));
                saw_source_encryption |= resource == encryption_network;
            }
            _ => return Err((Status::BadRequest, "capability-invalid".into())),
        }
        canonical_capabilities.push(capability.clone());
    }
    if !saw_source_kv || !saw_source_encryption {
        return Err((
            Status::Forbidden,
            "content-source-capability-mismatch".into(),
        ));
    }
    canonical_capabilities.sort_by_key(canonical_json_value);
    native.sort_by_key(canonical_json_value);
    Ok(RegistrationProjections {
        content_source_digest_hex: domain_digest_hex(
            CONTENT_SOURCE_DOMAIN,
            &Value::Object(source.clone()),
        ),
        capability_ceiling_hash_hex: domain_digest_hex(
            CAPABILITY_CEILING_DOMAIN,
            &Value::Array(canonical_capabilities),
        ),
        native_projection_hash_hex: domain_digest_hex(
            NATIVE_PROJECTION_DOMAIN,
            &Value::Array(native),
        ),
        attenuation: Value::Object(attenuation),
    })
}

fn domain_digest_hex(domain: &[u8], value: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical_json_value(value));
    hex::encode(hasher.finalize())
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn parse_policy_kv_resource(value: &str) -> Result<(String, String), (Status, String)> {
    // Policy/v2 SDKs use the ordinary TinyCloud resource form so the minted
    // capabilities flow directly through `/delegate` and `/invoke`. Keep the
    // original `tinycloud://<logical-space>/kv/<path>` parser below byte-for-
    // byte compatible for policy/v1 and already-registered documents.
    if !value.starts_with("tinycloud://") {
        let resource = value
            .parse::<ResourceId>()
            .map_err(|_| (Status::BadRequest, "kv-resource-invalid".into()))?;
        let path = resource
            .path()
            .filter(|_| {
                resource.service().as_str() == "kv"
                    && resource.query().is_none()
                    && resource.fragment().is_none()
            })
            .ok_or((Status::BadRequest, "kv-resource-invalid".into()))?;
        if path.as_str().is_empty()
            || path.as_str().starts_with('/')
            || path.as_str().ends_with('/')
            || path.as_str().contains("//")
            || path
                .as_str()
                .split('/')
                .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
        {
            return Err((Status::BadRequest, "kv-resource-invalid".into()));
        }
        return Ok((resource.space().to_string(), path.to_string()));
    }
    let rest = value
        .strip_prefix("tinycloud://")
        .ok_or((Status::BadRequest, "kv-resource-invalid".into()))?;
    let (space, path) = rest
        .split_once("/kv/")
        .ok_or((Status::BadRequest, "kv-resource-invalid".into()))?;
    if space.is_empty()
        || space.contains([':', '/', '?', '#', '%'])
        || path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains("//")
        || path
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err((Status::BadRequest, "kv-resource-invalid".into()));
    }
    Ok((space.to_owned(), path.to_owned()))
}

fn validate_policy_encryption_resource(value: &str) -> Result<(), (Status, String)> {
    let rest = value
        .strip_prefix("urn:tinycloud:encryption:")
        .ok_or((Status::BadRequest, "encryption-resource-invalid".into()))?;
    let (owner, network) = rest
        .rsplit_once(':')
        .ok_or((Status::BadRequest, "encryption-resource-invalid".into()))?;
    if !owner.starts_with("did:")
        || owner.len() <= 4
        || network.is_empty()
        || network.contains([':', '/', '%', '?', '#'])
    {
        return Err((Status::BadRequest, "encryption-resource-invalid".into()));
    }
    Ok(())
}

fn canonical_policy_actions(
    value: Option<&Value>,
    kv: bool,
) -> Result<Vec<String>, (Status, String)> {
    let array = value
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .ok_or((Status::BadRequest, "capability-actions-invalid".into()))?;
    let actions = array
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or((Status::BadRequest, "capability-actions-invalid".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut sorted = actions.clone();
    sorted.sort();
    sorted.dedup();
    if sorted != actions
        || kv
            && sorted.iter().any(|action| {
                !matches!(
                    action.as_str(),
                    "tinycloud.kv/get"
                        | "tinycloud.kv/list"
                        | "tinycloud.kv/metadata"
                        | "tinycloud.kv/put"
                )
            })
    {
        return Err((Status::BadRequest, "capability-actions-invalid".into()));
    }
    Ok(sorted)
}

fn canonical_value_set(values: &[Value]) -> Vec<Vec<u8>> {
    let mut values = values.iter().map(canonical_json_value).collect::<Vec<_>>();
    values.sort();
    values
}

fn validate_requested_policy_capabilities(
    requested: &[Value],
    ceiling: &[Value],
) -> Result<Vec<Value>, (Status, String)> {
    if requested.is_empty() {
        return Err((Status::BadRequest, "requested-capabilities-empty".into()));
    }
    let mut approved = Vec::with_capacity(requested.len());
    for candidate in requested {
        let object = candidate
            .as_object()
            .ok_or((Status::BadRequest, "requested-capability-invalid".into()))?;
        let contained = match object.get("kind").and_then(Value::as_str) {
            Some("kv") => {
                if object.len() != 4
                    || object.keys().any(|key| {
                        !["kind", "resource", "selector", "actions"].contains(&key.as_str())
                    })
                {
                    false
                } else {
                    let resource = object.get("resource").and_then(Value::as_str);
                    let selector = object.get("selector").and_then(Value::as_str);
                    let actions = canonical_policy_actions(object.get("actions"), true)?;
                    resource.is_some_and(|value| parse_policy_kv_resource(value).is_ok())
                        && matches!(selector, Some("exact" | "prefix"))
                        && ceiling.iter().any(|entry| {
                            let Some(parent) = entry.as_object() else {
                                return false;
                            };
                            let parent_resource = parent.get("resource").and_then(Value::as_str);
                            let parent_selector = parent.get("selector").and_then(Value::as_str);
                            let resource_contained =
                                match (parent_resource, resource, parent_selector) {
                                    (Some(parent), Some(child), Some("exact")) => {
                                        parent == child && selector == Some("exact")
                                    }
                                    (Some(parent), Some(child), Some("prefix")) => {
                                        parent == child
                                            || child
                                                .strip_prefix(parent)
                                                .is_some_and(|suffix| suffix.starts_with('/'))
                                    }
                                    _ => false,
                                };
                            parent.get("kind").and_then(Value::as_str) == Some("kv")
                                && resource_contained
                                && parent.get("actions").and_then(Value::as_array).is_some_and(
                                    |parent_actions| {
                                        actions.iter().all(|action| {
                                            parent_actions
                                                .iter()
                                                .any(|value| value.as_str() == Some(action))
                                        })
                                    },
                                )
                        })
                }
            }
            Some("encryption") => {
                object.len() == 3
                    && object
                        .keys()
                        .all(|key| ["kind", "resource", "action"].contains(&key.as_str()))
                    && object.get("action").and_then(Value::as_str)
                        == Some("tinycloud.encryption/decrypt")
                    && object
                        .get("resource")
                        .and_then(Value::as_str)
                        .is_some_and(|value| validate_policy_encryption_resource(value).is_ok())
                    && ceiling
                        .iter()
                        .any(|entry| canonical_json_value(entry) == canonical_json_value(candidate))
            }
            _ => false,
        };
        if !contained {
            return Err((
                Status::Forbidden,
                "requested-capability-not-contained".into(),
            ));
        }
        approved.push(candidate.clone());
    }
    approved.sort_by_key(canonical_json_value);
    if approved.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err((Status::BadRequest, "requested-capability-duplicate".into()));
    }
    Ok(approved)
}

fn attenuation_for_policy_capabilities(capabilities: &[Value]) -> Result<Value, (Status, String)> {
    let mut attenuation = serde_json::Map::new();
    for capability in capabilities {
        let object = capability
            .as_object()
            .ok_or((Status::BadRequest, "capability-invalid".into()))?;
        let resource = object
            .get("resource")
            .and_then(Value::as_str)
            .ok_or((Status::BadRequest, "capability-invalid".into()))?;
        let abilities = match object.get("kind").and_then(Value::as_str) {
            Some("kv") => {
                let selector = object
                    .get("selector")
                    .and_then(Value::as_str)
                    .ok_or((Status::BadRequest, "capability-invalid".into()))?;
                let caveat = serde_json::json!({
                    "kind": selector,
                    "type": "xyz.tinycloud.resource/selector",
                    "value": resource,
                });
                let actions = canonical_policy_actions(object.get("actions"), true)?;
                Value::Object(
                    actions
                        .into_iter()
                        .map(|action| (action, Value::Array(vec![caveat.clone()])))
                        .collect(),
                )
            }
            Some("encryption") => serde_json::json!({"tinycloud.encryption/decrypt": [{}]}),
            _ => return Err((Status::BadRequest, "capability-invalid".into())),
        };
        if attenuation.insert(resource.to_owned(), abilities).is_some() {
            return Err((Status::BadRequest, "capability-duplicate".into()));
        }
    }
    Ok(Value::Object(attenuation))
}

fn attenuation_contains(parent: &Value, child: &Value) -> bool {
    let (Some(parent), Some(child)) = (parent.as_object(), child.as_object()) else {
        return false;
    };
    child.iter().all(|(resource, child_abilities)| {
        let Some(child_abilities) = child_abilities.as_object() else {
            return false;
        };
        child_abilities.iter().all(|(ability, child_caveats)| {
            parent.iter().any(|(parent_resource, parent_abilities)| {
                parent_abilities
                    .as_object()
                    .and_then(|abilities| abilities.get(ability))
                    .is_some_and(|parent_caveats| {
                        attenuation_caveats_contain(
                            parent_resource,
                            parent_caveats,
                            resource,
                            child_caveats,
                        )
                    })
            })
        })
    })
}

fn attenuation_caveats_contain(
    parent_resource: &str,
    parent: &Value,
    child_resource: &str,
    child: &Value,
) -> bool {
    if parent_resource == child_resource
        && canonical_json_value(parent) == canonical_json_value(child)
    {
        return true;
    }
    fn selector(value: &Value) -> Option<(&str, &str)> {
        let values = value.as_array()?;
        if values.len() != 1 {
            return None;
        }
        let object = values[0].as_object()?;
        if object.len() != 3
            || object.get("type").and_then(Value::as_str) != Some("xyz.tinycloud.resource/selector")
            || object
                .keys()
                .any(|key| !["type", "kind", "value"].contains(&key.as_str()))
        {
            return None;
        }
        Some((
            object.get("kind").and_then(Value::as_str)?,
            object.get("value").and_then(Value::as_str)?,
        ))
    }
    let (Some((parent_kind, parent_value)), Some((child_kind, child_value))) =
        (selector(parent), selector(child))
    else {
        return false;
    };
    parent_kind == "prefix"
        && matches!(child_kind, "exact" | "prefix")
        && parent_value == parent_resource
        && child_value == child_resource
        && (child_resource == parent_resource
            || child_resource
                .strip_prefix(parent_resource)
                .is_some_and(|suffix| suffix.starts_with('/')))
}

fn validate_attested_enforcer_binding(
    value: &Value,
    enforcer_did: &str,
    node_did: &str,
    root_expiry: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<Vec<u8>, (Status, String)> {
    let object = value
        .as_object()
        .ok_or((Status::BadRequest, "enforcer-binding-invalid".into()))?;
    const KEYS: &[&str] = &[
        "schema",
        "enforcerDid",
        "nodeAudience",
        "attestationBindingDigestHex",
        "issuedAt",
        "expiresAt",
        "signature",
    ];
    if object.len() != KEYS.len()
        || object.keys().any(|key| !KEYS.contains(&key.as_str()))
        || object.get("schema").and_then(Value::as_str) != Some(ATTESTED_ENFORCER_V2_SCHEMA)
        || object.get("enforcerDid").and_then(Value::as_str) != Some(enforcer_did)
        || object.get("nodeAudience").and_then(Value::as_str) != Some(node_did)
        || !object
            .get("attestationBindingDigestHex")
            .and_then(Value::as_str)
            .is_some_and(is_lower_hex_digest)
    {
        return Err((Status::Forbidden, "enforcer-binding-invalid".into()));
    }
    let binding_material = serde_json::json!({
        "enforcerDid": enforcer_did,
        "nodeAudience": node_did,
    });
    let expected_binding_digest =
        hex::encode(Sha256::digest(canonical_json_value(&binding_material)));
    if object
        .get("attestationBindingDigestHex")
        .and_then(Value::as_str)
        != Some(expected_binding_digest.as_str())
    {
        return Err((Status::Forbidden, "enforcer-binding-invalid".into()));
    }
    let issued_text = object
        .get("issuedAt")
        .and_then(Value::as_str)
        .ok_or((Status::Forbidden, "enforcer-binding-time-invalid".into()))?;
    let expires_text = object
        .get("expiresAt")
        .and_then(Value::as_str)
        .ok_or((Status::Forbidden, "enforcer-binding-time-invalid".into()))?;
    let issued = parse_time(issued_text)
        .map_err(|_| (Status::Forbidden, "enforcer-binding-time-invalid".into()))?;
    let expires = parse_time(expires_text)
        .map_err(|_| (Status::Forbidden, "enforcer-binding-time-invalid".into()))?;
    if format_time(issued) != issued_text
        || format_time(expires) != expires_text
        || issued > now
        || expires <= now
        || expires > root_expiry
    {
        return Err((Status::Forbidden, "enforcer-binding-time-invalid".into()));
    }
    verify_signed_json(
        value,
        b"xyz.tinycloud.policy/AttestedEnforcerBinding/v2\0",
        node_did,
    )?;
    Ok(canonical_json_value(value))
}

fn validate_root_pair(
    request: &RegisterRequest,
    policy: &DelegationInfo,
    enforcement: &DelegationInfo,
    node_did: &str,
    projections: &RegistrationProjections,
) -> Result<(), (Status, String)> {
    let policy_role = fact(&policy.delegation, "role");
    let enforcement_role = fact(&enforcement.delegation, "role");
    let policy_owner = request
        .policy
        .get("ownerDid")
        .and_then(Value::as_str)
        .ok_or((Status::BadRequest, "policy-owner-missing".into()))?;
    let policy_id = request
        .policy
        .get("policyId")
        .and_then(Value::as_str)
        .ok_or((Status::BadRequest, "policy-id-missing".into()))?;
    let digest = policy_digest_hex(&request.policy)?;
    let root_attenuation = |delegation: &TinyCloudDelegation| -> Option<Value> {
        let TinyCloudDelegation::Ucan(ucan) = delegation else {
            return None;
        };
        serde_json::to_value(&ucan.payload().attenuation).ok()
    };
    if policy_role != Some("policy-authority")
        || enforcement_role != Some("policy-enforcement")
        || policy.delegator != enforcement.delegator
        || policy.delegator != policy_owner
        || fact(&policy.delegation, "ownerDid") != Some(policy_owner)
        || fact(&enforcement.delegation, "ownerDid") != Some(policy_owner)
        || fact(&policy.delegation, "policyId") != Some(policy_id)
        || fact(&enforcement.delegation, "policyId") != Some(policy_id)
        || fact(&policy.delegation, "policyDigestHex") != Some(digest.as_str())
        || fact(&enforcement.delegation, "policyDigestHex") != Some(digest.as_str())
        || fact(&policy.delegation, "policyCid") != Some(request.policy_cid.as_str())
        || fact(&enforcement.delegation, "policyCid") != Some(request.policy_cid.as_str())
        || policy.expiry != enforcement.expiry
        || policy.not_before != enforcement.not_before
        || policy.not_before.is_none()
        || policy.expiry.is_none()
        || policy.delegate != format!("did:tinycloud:policy:{}", digest)
        || enforcement.delegate != fact(&enforcement.delegation, "enforcerDid").unwrap_or_default()
        || fact(&policy.delegation, "nodeAudience") != Some(node_did)
        || fact(&enforcement.delegation, "nodeAudience") != Some(node_did)
        || fact(&policy.delegation, "contentSourceDigestHex")
            != Some(projections.content_source_digest_hex.as_str())
        || fact(&enforcement.delegation, "contentSourceDigestHex")
            != Some(projections.content_source_digest_hex.as_str())
        || fact(&policy.delegation, "capabilityCeilingHashHex")
            != Some(projections.capability_ceiling_hash_hex.as_str())
        || fact(&enforcement.delegation, "capabilityCeilingHashHex")
            != Some(projections.capability_ceiling_hash_hex.as_str())
        || fact(&policy.delegation, "nativeProjectionHashHex")
            != Some(projections.native_projection_hash_hex.as_str())
        || fact(&enforcement.delegation, "nativeProjectionHashHex")
            != Some(projections.native_projection_hash_hex.as_str())
        || root_attenuation(&policy.delegation).as_ref() != Some(&projections.attenuation)
        || root_attenuation(&enforcement.delegation).as_ref() != Some(&projections.attenuation)
        || canonical_root_capabilities(policy) != canonical_root_capabilities(enforcement)
    {
        return Err((Status::Forbidden, "sibling-root-mismatch".into()));
    }
    let created_at = request
        .policy
        .get("createdAt")
        .and_then(Value::as_str)
        .ok_or((Status::BadRequest, "policy-time-invalid".into()))
        .and_then(|value| {
            parse_time(value).map_err(|_| (Status::BadRequest, "policy-time-invalid".into()))
        })?;
    let policy_expires_at = request
        .policy
        .get("expiresAt")
        .and_then(Value::as_str)
        .map(parse_time)
        .transpose()
        .map_err(|_| (Status::BadRequest, "policy-time-invalid".into()))?;
    if policy
        .not_before
        .is_some_and(|not_before| not_before < created_at)
        || policy_expires_at.is_some_and(|expires_at| {
            policy
                .expiry
                .is_some_and(|root_expiry| root_expiry > expires_at)
        })
    {
        return Err((Status::Forbidden, "root-validity-outside-policy".into()));
    }
    if request.policy_cid.is_empty()
        || request.policy_cid == session_cid_from_bytes(request.policy_root.as_bytes())
        || request.policy_cid == session_cid_from_bytes(request.enforcement_root.as_bytes())
    {
        return Err((Status::Forbidden, "policy-cid-invalid".into()));
    }
    Ok(())
}

fn canonical_root_capabilities(value: &DelegationInfo) -> Vec<Vec<u8>> {
    let mut capabilities = value
        .capabilities
        .iter()
        .filter_map(|capability| serde_json::to_value(capability).ok())
        .map(|capability| canonical_json_value(&capability))
        .collect::<Vec<_>>();
    capabilities.sort();
    capabilities
}

fn root_expiry(value: &str) -> Result<String, ()> {
    let event = decode_delegation(value).map_err(|_| ())?;
    event.0.expiry.map(format_time).ok_or(())
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, (Status, String)> {
    Ok(canonical_json_value(value))
}
fn canonical_json_value(value: &Value) -> Vec<u8> {
    tinycloud_core::policy_capability::jcs::canonicalize(value)
}

fn status_field(bytes: &[u8], name: &str) -> Option<String> {
    serde_json::from_slice::<Value>(bytes)
        .ok()?
        .as_object()?
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn digest_value(value: &Value) -> String {
    hex::encode(Sha256::digest(canonical_json_value(value)))
}

fn policy_digest_hex(policy: &Value) -> Result<String, (Status, String)> {
    let mut unsigned = policy
        .as_object()
        .cloned()
        .ok_or((Status::BadRequest, "policy-invalid".into()))?;
    unsigned.remove("policyId");
    unsigned.remove("signature");
    let schema = policy
        .get("schema")
        .and_then(Value::as_str)
        .filter(|schema| matches!(*schema, POLICY_V1_SCHEMA | POLICY_V2_SCHEMA))
        .ok_or((Status::BadRequest, "policy-schema-unsupported".into()))?;
    let mut preimage = schema.as_bytes().to_vec();
    preimage.push(0);
    preimage.extend_from_slice(&canonical_json_value(&Value::Object(unsigned)));
    Ok(hex::encode(Sha256::digest(preimage)))
}

fn validate_registration_projection(
    registration: &policy_v3_registration::Model,
) -> Result<Value, (Status, String)> {
    let policy: Value = serde_json::from_slice(&registration.policy_bytes)
        .map_err(|_| (Status::Forbidden, "policy-registration-corrupt".into()))?;
    if canonical_json_value(&policy) != registration.policy_bytes {
        return Err((Status::Forbidden, "policy-registration-corrupt".into()));
    }
    validate_policy_document(
        &policy,
        &registration.policy_bytes,
        &registration.policy_cid,
    )?;
    let projections = registration_projections(&policy)?;
    if policy_digest_hex(&policy)? != registration.policy_digest_hex
        || policy.get("ownerDid").and_then(Value::as_str) != Some(registration.owner_did.as_str())
        || projections.content_source_digest_hex != registration.content_source_digest_hex
        || projections.native_projection_hash_hex != registration.native_projection_hash_hex
    {
        return Err((
            Status::Forbidden,
            "policy-registration-projection-mismatch".into(),
        ));
    }
    Ok(policy)
}

struct ClaimPresentationContext<'a> {
    challenge_id: &'a str,
    nonce: &'a str,
    policy_cid: &'a str,
    owner_did: &'a str,
    recipient_did: &'a str,
    authenticated_account_owner: Option<&'a str>,
    now: OffsetDateTime,
}

fn validate_claim_and_presentation(
    claim: &Value,
    presentation: &Value,
    context: &ClaimPresentationContext<'_>,
) -> Result<(), (Status, String)> {
    let ClaimPresentationContext {
        challenge_id,
        nonce,
        policy_cid,
        owner_did,
        recipient_did,
        now,
        ..
    } = context;
    let claim = claim
        .as_object()
        .ok_or((Status::BadRequest, "claim-invalid".into()))?;
    let presentation = presentation
        .as_object()
        .ok_or((Status::BadRequest, "presentation-invalid".into()))?;
    const CLAIM_KEYS: &[&str] = &[
        "schema",
        "jti",
        "challengeId",
        "nonce",
        "policyCid",
        "issuerDid",
        "subjectDid",
        "holderDid",
        "recipientDid",
        "requestedCapabilities",
        "credentialEvidence",
        "issuedAt",
        "expiresAt",
        "signature",
    ];
    const PRESENTATION_KEYS: &[&str] = &[
        "schema",
        "jti",
        "challengeId",
        "nonce",
        "policyCid",
        "holderDid",
        "subjectDid",
        "requestedCapabilities",
        "vpBytesBase64",
        "issuedAt",
        "expiresAt",
        "signature",
    ];
    if claim.len() != CLAIM_KEYS.len()
        || claim.keys().any(|key| !CLAIM_KEYS.contains(&key.as_str()))
        || presentation.len() != PRESENTATION_KEYS.len()
        || presentation
            .keys()
            .any(|key| !PRESENTATION_KEYS.contains(&key.as_str()))
        || claim.get("schema").and_then(Value::as_str) != Some("xyz.tinycloud.policy/claim/v2")
        || presentation.get("schema").and_then(Value::as_str)
            != Some("xyz.tinycloud.policy/presentation/v2")
    {
        return Err((
            Status::BadRequest,
            "claim-or-presentation-schema-invalid".into(),
        ));
    }
    if claim.get("policyCid").and_then(Value::as_str) != Some(policy_cid)
        || presentation.get("policyCid").and_then(Value::as_str) != Some(policy_cid)
        || claim.get("issuerDid").and_then(Value::as_str) != Some(owner_did)
        || claim.get("subjectDid").and_then(Value::as_str) != Some(recipient_did)
        || presentation.get("subjectDid").and_then(Value::as_str) != Some(recipient_did)
    {
        return Err((Status::Forbidden, "claim-principal-binding-invalid".into()));
    }
    for (object, name) in [(claim, "claim"), (presentation, "presentation")] {
        if object.get("challengeId").and_then(Value::as_str) != Some(challenge_id)
            || object.get("nonce").and_then(Value::as_str) != Some(nonce)
            || object.get("jti").and_then(Value::as_str).is_none()
        {
            return Err((Status::Forbidden, format!("{name}-binding-invalid")));
        }
        let signature = object
            .get("signature")
            .and_then(Value::as_object)
            .ok_or((Status::Forbidden, format!("{name}-signature-missing")))?;
        if signature.len() != 3
            || signature
                .keys()
                .any(|key| !["suite", "signerDid", "value"].contains(&key.as_str()))
            || signature.get("suite").and_then(Value::as_str) != Some("Ed25519")
            || signature.get("signerDid").and_then(Value::as_str).is_none()
            || signature.get("value").and_then(Value::as_str).is_none()
        {
            return Err((Status::Forbidden, format!("{name}-signature-invalid")));
        }
        let expected_signer = if name == "claim" {
            owner_did
        } else {
            recipient_did
        };
        if signature.get("signerDid").and_then(Value::as_str) != Some(expected_signer) {
            return Err((Status::Forbidden, format!("{name}-signer-untrusted")));
        }
        let mut unsigned = Value::Object(object.clone());
        unsigned
            .as_object_mut()
            .expect("object was created from a map")
            .remove("signature");
        let domain = if name == "claim" {
            b"xyz.tinycloud.policy/Claim/v2\0".as_slice()
        } else {
            b"xyz.tinycloud.policy/Presentation/v2\0".as_slice()
        };
        let mut signed = domain.to_vec();
        signed.extend_from_slice(&canonical_json_value(&unsigned));
        let signature_bytes = decode_config(
            signature
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            URL_SAFE_NO_PAD,
        )
        .map_err(|_| (Status::Forbidden, format!("{name}-signature-invalid")))?;
        if signature_bytes.len() != 64 {
            return Err((Status::Forbidden, format!("{name}-signature-invalid")));
        }
        tinycloud_auth::share_email_evidence::verify_detached_ed25519(
            expected_signer,
            &Sha256::digest(signed),
            &signature_bytes,
        )
        .map_err(|_| (Status::Forbidden, format!("{name}-signature-invalid")))?;
    }
    if presentation
        .get("holderDid")
        .and_then(Value::as_str)
        .is_none()
    {
        return Err((Status::Forbidden, "presentation-holder-missing".into()));
    }
    if presentation.get("holderDid").and_then(Value::as_str) != Some(recipient_did)
        || claim.get("recipientDid").and_then(Value::as_str) != Some(recipient_did)
    {
        return Err((Status::Forbidden, "recipient-binding-invalid".into()));
    }
    for (object, label) in [(claim, "claim"), (presentation, "presentation")] {
        let issued = object
            .get("issuedAt")
            .and_then(Value::as_str)
            .ok_or((Status::Forbidden, format!("{label}-time-invalid")))?;
        let expires = object
            .get("expiresAt")
            .and_then(Value::as_str)
            .ok_or((Status::Forbidden, format!("{label}-time-invalid")))?;
        let issued_at =
            parse_time(issued).map_err(|_| (Status::Forbidden, format!("{label}-time-invalid")))?;
        let expires_at = parse_time(expires)
            .map_err(|_| (Status::Forbidden, format!("{label}-time-invalid")))?;
        if format_time(issued_at) != issued
            || format_time(expires_at) != expires
            || issued_at > *now
            || expires_at <= *now
            || expires_at - issued_at > Duration::seconds(300)
        {
            return Err((Status::Forbidden, format!("{label}-time-invalid")));
        }
    }
    credential_evidence_digest(
        claim
            .get("credentialEvidence")
            .ok_or((Status::Forbidden, "credential-evidence-missing".into()))?,
    )?;
    if claim["credentialEvidence"]
        .as_array()
        .is_none_or(|evidence| {
            evidence.iter().any(|descriptor| {
                descriptor.get("issuerDid").and_then(Value::as_str) != Some(owner_did)
                    || descriptor.get("subjectDid").and_then(Value::as_str) != Some(recipient_did)
            })
        })
    {
        return Err((
            Status::Forbidden,
            "credential-principal-binding-invalid".into(),
        ));
    }
    let vp = presentation
        .get("vpBytesBase64")
        .and_then(Value::as_str)
        .ok_or((Status::Forbidden, "presentation-bytes-missing".into()))?;
    if decode_config(vp, URL_SAFE_NO_PAD).is_err() {
        return Err((Status::Forbidden, "presentation-bytes-invalid".into()));
    }
    Ok(())
}

fn credential_evidence_digest(value: &Value) -> Result<String, (Status, String)> {
    let evidence = value
        .as_array()
        .filter(|items| !items.is_empty())
        .ok_or((Status::Forbidden, "credential-evidence-invalid".into()))?;
    let mut normalized = Vec::with_capacity(evidence.len());
    for descriptor in evidence {
        let object = descriptor
            .as_object()
            .ok_or((Status::Forbidden, "credential-evidence-invalid".into()))?;
        if object.len() != 4
            || object.keys().any(|key| {
                !["format", "issuerDid", "subjectDid", "digestHex"].contains(&key.as_str())
            })
            || object
                .get("format")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || object
                .get("issuerDid")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || object
                .get("subjectDid")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || !object
                .get("digestHex")
                .and_then(Value::as_str)
                .is_some_and(is_lower_hex_digest)
        {
            return Err((Status::Forbidden, "credential-evidence-invalid".into()));
        }
        normalized.push(descriptor.clone());
    }
    normalized.sort_by_key(canonical_json_value);
    Ok(domain_digest_hex(
        b"xyz.tinycloud.policy/CredentialEvidence/v1\0",
        &Value::Array(normalized),
    ))
}

struct CredentialAdmissionV3 {
    credential_id: String,
    credential_digest: String,
    envelope_digest_hex: String,
    presentation_digest_hex: String,
    credential_space_owner_did: String,
}

struct AccountOwnerProof {
    cid: tinycloud_auth::ipld_core::cid::Cid,
    row: delegation_model::Model,
    owner_did: String,
    space: SpaceId,
    expires_at: Option<OffsetDateTime>,
}

/// Authenticate the policy/v2 credential owner from an already-admitted
/// ordinary TinyCloud account session. The CID is only an address: authority
/// comes from the exact stored CACAO bytes, their current signature/time, the
/// separately addressed credentials-space authority, the holder audience,
/// and the hosted-space and revocation state in this Node.
async fn authenticate_account_owner(
    authorization_cid: Option<&str>,
    credential_space_id: Option<&str>,
    holder_did: &str,
    runtime: &PolicyV3Runtime,
    tinycloud: &crate::TinyCloud,
) -> Result<AccountOwnerProof, (Status, String)> {
    let cid = authorization_cid
        .ok_or((Status::BadRequest, "account-authorization-required".into()))?
        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
        .map_err(|_| (Status::Forbidden, "account-authorization-invalid".into()))?;
    let (row, event) = tinycloud
        .load_signed_delegation(cid)
        .await
        .map_err(|_| (Status::Forbidden, "account-authorization-invalid".into()))?
        .ok_or((Status::Forbidden, "account-authorization-missing".into()))?;
    if !holder_did.starts_with("did:key:") {
        return Err((Status::Forbidden, "account-holder-invalid".into()));
    }
    if !event.0.parents.is_empty() {
        return Err((Status::Forbidden, "account-authorization-not-root".into()));
    }
    if event.0.delegate != holder_did {
        return Err((
            Status::Forbidden,
            "account-authorization-audience-invalid".into(),
        ));
    }
    if row.delegator != event.0.delegator
        || row.delegatee != event.0.delegate
        || row.expiry != event.0.expiry
        || row.not_before != event.0.not_before
        || row.issued_at != event.0.issued_at
    {
        return Err((
            Status::Forbidden,
            "account-authorization-projection-invalid".into(),
        ));
    }
    let TinyCloudDelegation::Cacao(cacao) = &event.0.delegation else {
        return Err((Status::Forbidden, "account-authorization-not-cacao".into()));
    };
    cacao.verify().await.map_err(|_| {
        (
            Status::Forbidden,
            "account-authorization-signature-invalid".into(),
        )
    })?;
    if !cacao.payload().valid_now() {
        return Err((Status::Forbidden, "account-authorization-inactive".into()));
    }

    let owner_did = event.0.delegator.clone();
    if parse_pkh_did(&owner_did)
        .map_err(|_| (Status::Forbidden, "credential-space-owner-invalid".into()))?
        .is_none()
    {
        return Err((Status::Forbidden, "credential-space-owner-invalid".into()));
    }
    let credentials_space = credential_space_id
        .ok_or((Status::BadRequest, "credential-space-required".into()))?
        .parse::<SpaceId>()
        .map_err(|_| (Status::Forbidden, "credential-space-invalid".into()))?;
    if credentials_space.name().as_str() != "credentials"
        || parse_pkh_did(credentials_space.did().as_str())
            .map_err(|_| (Status::Forbidden, "credential-space-invalid".into()))?
            .is_none()
        || !did_principal_matches(credentials_space.did().as_str(), &owner_did)
    {
        return Err((
            Status::Forbidden,
            "credential-space-owner-binding-invalid".into(),
        ));
    }
    let hosted_credentials_space = tinycloud_core::types::Resource::from(
        credentials_space
            .clone()
            .to_resource("space".parse().map_err(bad)?, None, None, None),
    );
    let credential_namespace =
        tinycloud_core::types::Resource::from(credentials_space.clone().to_resource(
            "kv".parse().map_err(bad)?,
            Some("v1/".parse().map_err(bad)?),
            None,
            None,
        ));
    let hosts_space = event.0.capabilities.iter().any(|capability| {
        capability.ability.as_ref().as_ref() == "tinycloud.space/host"
            && capability.resource == hosted_credentials_space
    });
    let controls_credential_namespace =
        ["tinycloud.kv/get", "tinycloud.kv/put"]
            .iter()
            .all(|ability| {
                event.0.capabilities.iter().any(|capability| {
                    capability.ability.as_ref().as_ref() == *ability
                        && credential_namespace.extends(&capability.resource)
                })
            });
    if !hosts_space && !controls_credential_namespace {
        return Err((
            Status::Forbidden,
            "account-authorization-capability-mismatch".into(),
        ));
    }
    if revocation::Entity::find()
        .filter(revocation::Column::Revoked.eq(row.id))
        .one(&runtime.conn)
        .await
        .map_err(db_error)?
        .is_some()
        || space::Entity::find_by_id(SpaceIdWrap(credentials_space.clone()))
            .one(&runtime.conn)
            .await
            .map_err(db_error)?
            .is_none()
    {
        return Err((Status::Forbidden, "account-authorization-inactive".into()));
    }
    Ok(AccountOwnerProof {
        cid,
        row,
        owner_did,
        space: credentials_space,
        expires_at: event.0.expiry,
    })
}

async fn validate_locked_account_owner(
    transaction: &DatabaseTransaction,
    proof: &AccountOwnerProof,
) -> Result<(), (Status, String)> {
    let locked = delegation_model::Entity::find_by_id(proof.row.id)
        .lock_exclusive()
        .one(transaction)
        .await
        .map_err(db_error)?
        .ok_or((Status::Conflict, "account-authorization-changed".into()))?;
    if locked != proof.row
        || locked.id != tinycloud_core::hash::Hash::from(proof.cid)
        || proof
            .expires_at
            .is_some_and(|expires_at| expires_at <= OffsetDateTime::now_utc())
        || revocation::Entity::find()
            .filter(revocation::Column::Revoked.eq(locked.id))
            .one(transaction)
            .await
            .map_err(db_error)?
            .is_some()
        || space::Entity::find_by_id(SpaceIdWrap(proof.space.clone()))
            .one(transaction)
            .await
            .map_err(db_error)?
            .is_none()
    {
        return Err((Status::Conflict, "account-authorization-changed".into()));
    }
    Ok(())
}

fn validate_credential_admission_v3(
    requirement: &Value,
    credential: &Value,
    presentation: &Value,
    policy: &Value,
    context: &ClaimPresentationContext<'_>,
    runtime: &PolicyV3Runtime,
    requested_capabilities: &[Value],
) -> Result<CredentialAdmissionV3, (Status, String)> {
    let projection = validate_policy_credential_requirement(
        policy
            .get("credentialRequirement")
            .ok_or((Status::Forbidden, "credential-requirement-missing".into()))?,
    )?;
    validate_request_local_requirement(requirement, projection)?;
    let issuer = runtime.credential_issuer.as_ref().ok_or((
        Status::ServiceUnavailable,
        "credential-issuer-unavailable".into(),
    ))?;
    let verified = verify_opencredentials_credential(
        credential,
        requirement,
        projection,
        issuer,
        context.recipient_did,
        context.now,
    )?;
    let presentation = presentation
        .as_object()
        .ok_or((Status::BadRequest, "presentation-invalid".into()))?;
    const PRESENTATION_KEYS: &[&str] = &[
        "schema",
        "jti",
        "challengeId",
        "nonce",
        "policyCid",
        "nodeAudience",
        "holderDid",
        "subjectDid",
        "credentialSpaceOwnerDid",
        "credentialDigest",
        "requirementDigest",
        "descriptorDigest",
        "requestedCapabilities",
        "issuedAt",
        "expiresAt",
        "signature",
    ];
    if presentation.len() != PRESENTATION_KEYS.len()
        || presentation
            .keys()
            .any(|key| !PRESENTATION_KEYS.contains(&key.as_str()))
        || presentation.get("schema").and_then(Value::as_str)
            != Some(CREDENTIAL_PRESENTATION_V3_SCHEMA)
        || presentation
            .get("jti")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || presentation.get("challengeId").and_then(Value::as_str) != Some(context.challenge_id)
        || presentation.get("nonce").and_then(Value::as_str) != Some(context.nonce)
        || presentation.get("policyCid").and_then(Value::as_str) != Some(context.policy_cid)
        || presentation.get("nodeAudience").and_then(Value::as_str)
            != Some(runtime.node_did.as_str())
        || presentation.get("holderDid").and_then(Value::as_str) != Some(context.recipient_did)
        || presentation.get("subjectDid").and_then(Value::as_str) != Some(context.recipient_did)
        || presentation.get("credentialDigest").and_then(Value::as_str)
            != Some(verified.credential_digest.as_str())
        || presentation
            .get("requirementDigest")
            .and_then(Value::as_str)
            != projection.get("requirementDigest").and_then(Value::as_str)
        || presentation.get("descriptorDigest").and_then(Value::as_str)
            != projection.get("descriptorDigest").and_then(Value::as_str)
        || canonical_value_set(
            presentation
                .get("requestedCapabilities")
                .and_then(Value::as_array)
                .ok_or((
                    Status::Forbidden,
                    "presentation-capabilities-mismatch".into(),
                ))?,
        ) != canonical_value_set(requested_capabilities)
    {
        return Err((
            Status::Forbidden,
            "credential-presentation-binding-invalid".into(),
        ));
    }
    let account_owner = presentation
        .get("credentialSpaceOwnerDid")
        .and_then(Value::as_str)
        .ok_or((
            Status::Forbidden,
            "credential-space-owner-binding-invalid".into(),
        ))?;
    if Some(account_owner) != context.authenticated_account_owner {
        return Err((
            Status::Forbidden,
            "credential-space-owner-binding-invalid".into(),
        ));
    }
    let signer = validate_v3_presentation_signature(presentation, context.recipient_did)?;
    if signer != context.recipient_did {
        return Err((Status::Forbidden, "presentation-signer-untrusted".into()));
    }
    validate_fresh_window(presentation, context.now, "presentation")?;
    Ok(CredentialAdmissionV3 {
        credential_id: verified.credential_id,
        credential_digest: verified.credential_digest,
        envelope_digest_hex: digest_value(credential),
        presentation_digest_hex: hex::encode(Sha256::digest(canonical_json_value(&Value::Object(
            presentation.clone(),
        )))),
        credential_space_owner_did: account_owner.to_owned(),
    })
}

fn validate_request_local_requirement(
    requirement: &Value,
    projection: &serde_json::Map<String, Value>,
) -> Result<(), (Status, String)> {
    let object = requirement
        .as_object()
        .ok_or((Status::BadRequest, "credential-requirement-invalid".into()))?;
    const REQUIRED_KEYS: &[&str] = &["type", "version", "profile", "credentialType", "claims"];
    const ALLOWED_KEYS: &[&str] = &[
        "type",
        "version",
        "profile",
        "credentialType",
        "claims",
        "maxAgeSeconds",
    ];
    if object
        .keys()
        .any(|key| !ALLOWED_KEYS.contains(&key.as_str()))
        || !REQUIRED_KEYS.iter().all(|key| object.contains_key(*key))
        || object.get("type").and_then(Value::as_str) != Some("TinyCloudCredentialRequirement")
        || object.get("version").and_then(Value::as_u64) != Some(1)
        || !versioned_identifier(object.get("profile"))
        || !versioned_identifier(object.get("credentialType"))
        || object.get("profile") != projection.get("profile")
        || object.get("credentialType") != projection.get("credentialType")
        || object
            .get("claims")
            .and_then(Value::as_object)
            .is_none_or(|claims| {
                claims.is_empty()
                    || claims.iter().any(|(name, value)| {
                        name.is_empty()
                            || name.len() > 128
                            || value
                                .as_str()
                                .is_none_or(|value| value.is_empty() || value.len() > 4096)
                    })
            })
        || object.get("maxAgeSeconds").is_some_and(|value| {
            value
                .as_u64()
                .is_none_or(|seconds| seconds == 0 || seconds > i64::MAX as u64)
        })
        || projection.get("requirementDigest").and_then(Value::as_str)
            != Some(canonical_digest_base64url(requirement).as_str())
    {
        return Err((
            Status::Forbidden,
            "credential-requirement-substituted".into(),
        ));
    }
    Ok(())
}

struct VerifiedOpenCredential {
    credential_id: String,
    credential_digest: String,
}

fn verify_opencredentials_credential(
    envelope: &Value,
    requirement: &Value,
    projection: &serde_json::Map<String, Value>,
    trusted_issuer: &IssuerKey,
    expected_holder: &str,
    now: OffsetDateTime,
) -> Result<VerifiedOpenCredential, (Status, String)> {
    if !trusted_issuer.enabled || trusted_issuer.key_version == 0 {
        return Err((Status::Forbidden, "credential-issuer-untrusted".into()));
    }
    let envelope = envelope
        .as_object()
        .ok_or((Status::BadRequest, "credential-envelope-invalid".into()))?;
    const ENVELOPE_KEYS: &[&str] = &[
        "type",
        "version",
        "protocol",
        "profile",
        "credentialType",
        "schema",
        "format",
        "issuerDid",
        "issuerKid",
        "subjectDid",
        "holderDid",
        "claims",
        "claimsDigest",
        "descriptorDigest",
        "credentialId",
        "issuedAt",
        "notBefore",
        "expiresAt",
        "status",
        "credential",
    ];
    if envelope.len() != ENVELOPE_KEYS.len()
        || envelope
            .keys()
            .any(|key| !ENVELOPE_KEYS.contains(&key.as_str()))
        || envelope.get("type").and_then(Value::as_str) != Some("OpenCredentialsIssuedCredential")
        || envelope.get("version").and_then(Value::as_u64) != Some(1)
        || envelope.get("protocol").and_then(Value::as_str)
            != Some("tinycloud.credentials/acquisition/v1")
        || envelope.get("format").and_then(Value::as_str) != Some("vc+sd-jwt")
        || envelope.get("profile") != projection.get("profile")
        || envelope.get("credentialType") != projection.get("credentialType")
        || envelope.get("schema").and_then(Value::as_str)
            != projection
                .get("credentialType")
                .and_then(Value::as_object)
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str)
        || envelope.get("issuerDid").and_then(Value::as_str)
            != projection.get("issuerDid").and_then(Value::as_str)
        || envelope.get("issuerKid").and_then(Value::as_str)
            != projection.get("issuerKid").and_then(Value::as_str)
        || envelope.get("issuerDid").and_then(Value::as_str)
            != Some(trusted_issuer.issuer_did.as_str())
        || envelope.get("issuerKid").and_then(Value::as_str) != Some(trusted_issuer.kid.as_str())
        || envelope.get("subjectDid").and_then(Value::as_str) != Some(expected_holder)
        || envelope.get("holderDid").and_then(Value::as_str) != Some(expected_holder)
        || envelope.get("descriptorDigest").and_then(Value::as_str)
            != projection.get("descriptorDigest").and_then(Value::as_str)
        || envelope
            .get("status")
            .and_then(Value::as_object)
            .is_none_or(|status| {
                status.len() != 2
                    || status.get("method").and_then(Value::as_str) != Some("none")
                    || status
                        .get("freshnessSeconds")
                        .and_then(Value::as_u64)
                        .is_none_or(|seconds| seconds == 0)
            })
    {
        return Err((Status::Forbidden, "credential-envelope-invalid".into()));
    }
    let credential = envelope
        .get("credential")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 65_536)
        .ok_or((Status::Forbidden, "credential-invalid".into()))?;
    let mut sd_parts = credential.split('~');
    let compact = sd_parts
        .next()
        .ok_or((Status::Forbidden, "credential-invalid".into()))?;
    let disclosures = sd_parts.filter(|part| !part.is_empty()).collect::<Vec<_>>();
    let jwt = compact.split('.').collect::<Vec<_>>();
    if jwt.len() != 3 || jwt.iter().any(|part| part.is_empty()) {
        return Err((Status::Forbidden, "credential-invalid".into()));
    }
    let header = decode_base64url_json(jwt[0])?;
    let payload = decode_base64url_json(jwt[1])?;
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA")
        || header
            .get("typ")
            .is_some_and(|value| value.as_str() != Some("vc+sd-jwt"))
        || header
            .get("kid")
            .is_some_and(|value| value.as_str() != Some(trusted_issuer.kid.as_str()))
    {
        return Err((Status::Forbidden, "credential-signature-invalid".into()));
    }
    let signature = decode_base64url(jwt[2])?;
    if signature.len() != 64 {
        return Err((Status::Forbidden, "credential-signature-invalid".into()));
    }
    verify_issuer_signature(
        &trusted_issuer.public_key,
        format!("{}.{}", jwt[0], jwt[1]).as_bytes(),
        &signature,
    )?;
    let mut disclosed = payload
        .as_object()
        .cloned()
        .ok_or((Status::Forbidden, "credential-invalid".into()))?;
    let signed_disclosures = disclosed
        .get("_sd")
        .and_then(Value::as_array)
        .cloned()
        .ok_or((Status::Forbidden, "credential-invalid".into()))?;
    if disclosed.get("_sd_alg").and_then(Value::as_str) != Some("sha-256")
        || signed_disclosures.iter().any(|digest| {
            digest
                .as_str()
                .is_none_or(|digest| !is_base64url_digest(digest))
        })
    {
        return Err((Status::Forbidden, "credential-invalid".into()));
    }
    for disclosure in disclosures {
        let digest = base64::encode_config(Sha256::digest(disclosure.as_bytes()), URL_SAFE_NO_PAD);
        if !signed_disclosures
            .iter()
            .any(|candidate| candidate.as_str() == Some(digest.as_str()))
        {
            return Err((Status::Forbidden, "credential-disclosure-invalid".into()));
        }
        let item = decode_base64url_json_array(disclosure)?;
        if item.len() != 3 || item[0].as_str().is_none() || item[1].as_str().is_none() {
            return Err((Status::Forbidden, "credential-disclosure-invalid".into()));
        }
        let Some(name) = item[1].as_str() else {
            return Err((Status::Forbidden, "credential-disclosure-invalid".into()));
        };
        if disclosed.insert(name.to_owned(), item[2].clone()).is_some() {
            return Err((Status::Forbidden, "credential-disclosure-invalid".into()));
        }
    }
    let binding = disclosed
        .get("holderBinding")
        .and_then(Value::as_object)
        .ok_or((
            Status::Forbidden,
            "credential-holder-binding-invalid".into(),
        ))?;
    if disclosed.get("iss").and_then(Value::as_str) != Some(trusted_issuer.issuer_did.as_str())
        || disclosed.get("sub").and_then(Value::as_str) != Some(expected_holder)
        || disclosed.get("vct").and_then(Value::as_str) != Some(trusted_issuer.vct.as_str())
        || disclosed.get("profile").and_then(Value::as_str)
            != projection
                .get("profile")
                .and_then(Value::as_object)
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str)
        || disclosed.get("profileVersion").and_then(Value::as_u64) != Some(1)
        || disclosed.get("descriptorDigest").and_then(Value::as_str)
            != projection.get("descriptorDigest").and_then(Value::as_str)
        || binding.len() != 2
        || binding.get("did").and_then(Value::as_str) != Some(expected_holder)
        || binding.get("signingDomain").and_then(Value::as_str)
            != Some("tinycloud.credentials/holder-binding/v1")
    {
        return Err((
            Status::Forbidden,
            "credential-holder-binding-invalid".into(),
        ));
    }
    let requirement_claims = requirement
        .get("claims")
        .and_then(Value::as_object)
        .ok_or((Status::Forbidden, "credential-requirement-invalid".into()))?;
    let envelope_claims = envelope
        .get("claims")
        .and_then(Value::as_object)
        .ok_or((Status::Forbidden, "credential-claims-invalid".into()))?;
    if requirement_claims.iter().any(|(name, expected)| {
        disclosed.get(name) != Some(expected) || envelope_claims.get(name) != Some(expected)
    }) || canonical_digest_base64url(&Value::Object(envelope_claims.clone()))
        != envelope
            .get("claimsDigest")
            .and_then(Value::as_str)
            .unwrap_or_default()
    {
        return Err((
            Status::Forbidden,
            "credential-requirement-not-satisfied".into(),
        ));
    }
    validate_credential_time(envelope, &disclosed, requirement, now)?;
    let credential_id = disclosed
        .get("jti")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or((Status::Forbidden, "credential-invalid".into()))?;
    if envelope.get("credentialId").and_then(Value::as_str) != Some(credential_id) {
        return Err((Status::Forbidden, "credential-invalid".into()));
    }
    Ok(VerifiedOpenCredential {
        credential_id: credential_id.to_owned(),
        credential_digest: base64::encode_config(
            Sha256::digest(credential.as_bytes()),
            URL_SAFE_NO_PAD,
        ),
    })
}

fn validate_v3_presentation_signature<'a>(
    presentation: &'a serde_json::Map<String, Value>,
    expected_holder: &str,
) -> Result<&'a str, (Status, String)> {
    let signature = presentation
        .get("signature")
        .and_then(Value::as_object)
        .ok_or((Status::Forbidden, "presentation-signature-missing".into()))?;
    let signer = signature
        .get("signerDid")
        .and_then(Value::as_str)
        .ok_or((Status::Forbidden, "presentation-signature-invalid".into()))?;
    if signature.len() != 3
        || signature.get("suite").and_then(Value::as_str) != Some("Ed25519")
        || signer != expected_holder
    {
        return Err((Status::Forbidden, "presentation-signer-untrusted".into()));
    }
    let bytes = decode_base64url(
        signature
            .get("value")
            .and_then(Value::as_str)
            .ok_or((Status::Forbidden, "presentation-signature-invalid".into()))?,
    )?;
    let mut unsigned = Value::Object(presentation.clone());
    unsigned
        .as_object_mut()
        .ok_or((Status::Forbidden, "presentation-signature-invalid".into()))?
        .remove("signature");
    let mut preimage = CREDENTIAL_PRESENTATION_V3_DOMAIN.to_vec();
    preimage.extend_from_slice(&canonical_json_value(&unsigned));
    verify_detached_ed25519(signer, &Sha256::digest(preimage), &bytes)
        .map_err(|_| (Status::Forbidden, "presentation-signature-invalid".into()))?;
    Ok(signer)
}

fn validate_fresh_window(
    object: &serde_json::Map<String, Value>,
    now: OffsetDateTime,
    label: &str,
) -> Result<(), (Status, String)> {
    let issued_text = object
        .get("issuedAt")
        .and_then(Value::as_str)
        .ok_or((Status::Forbidden, format!("{label}-time-invalid")))?;
    let expires_text = object
        .get("expiresAt")
        .and_then(Value::as_str)
        .ok_or((Status::Forbidden, format!("{label}-time-invalid")))?;
    let issued = parse_time(issued_text)
        .map_err(|_| (Status::Forbidden, format!("{label}-time-invalid")))?;
    let expires = parse_time(expires_text)
        .map_err(|_| (Status::Forbidden, format!("{label}-time-invalid")))?;
    if format_time(issued) != issued_text
        || format_time(expires) != expires_text
        || issued > now
        || expires <= now
        || expires - issued > Duration::seconds(300)
    {
        return Err((Status::Forbidden, format!("{label}-time-invalid")));
    }
    Ok(())
}

fn validate_credential_time(
    envelope: &serde_json::Map<String, Value>,
    disclosed: &serde_json::Map<String, Value>,
    requirement: &Value,
    now: OffsetDateTime,
) -> Result<(), (Status, String)> {
    let issued = parse_time(
        envelope
            .get("issuedAt")
            .and_then(Value::as_str)
            .ok_or((Status::Forbidden, "credential-time-invalid".into()))?,
    )
    .map_err(|_| (Status::Forbidden, "credential-time-invalid".into()))?;
    let not_before = parse_time(
        envelope
            .get("notBefore")
            .and_then(Value::as_str)
            .ok_or((Status::Forbidden, "credential-time-invalid".into()))?,
    )
    .map_err(|_| (Status::Forbidden, "credential-time-invalid".into()))?;
    let expires = parse_time(
        envelope
            .get("expiresAt")
            .and_then(Value::as_str)
            .ok_or((Status::Forbidden, "credential-time-invalid".into()))?,
    )
    .map_err(|_| (Status::Forbidden, "credential-time-invalid".into()))?;
    if not_before > now
        || expires <= now
        || disclosed.get("iat").and_then(Value::as_i64) != Some(issued.unix_timestamp())
        || disclosed.get("nbf").and_then(Value::as_i64) != Some(not_before.unix_timestamp())
        || disclosed.get("exp").and_then(Value::as_i64) != Some(expires.unix_timestamp())
        || requirement
            .get("maxAgeSeconds")
            .and_then(Value::as_i64)
            .is_some_and(|max_age| now - issued > Duration::seconds(max_age))
    {
        return Err((Status::Forbidden, "credential-time-invalid".into()));
    }
    Ok(())
}

fn decode_base64url(value: &str) -> Result<Vec<u8>, (Status, String)> {
    let bytes = decode_config(value, URL_SAFE_NO_PAD)
        .map_err(|_| (Status::Forbidden, "credential-encoding-invalid".into()))?;
    if base64::encode_config(&bytes, URL_SAFE_NO_PAD) != value {
        return Err((Status::Forbidden, "credential-encoding-invalid".into()));
    }
    Ok(bytes)
}

fn decode_base64url_json(value: &str) -> Result<Value, (Status, String)> {
    serde_json::from_slice(&decode_base64url(value)?)
        .map_err(|_| (Status::Forbidden, "credential-json-invalid".into()))
}

fn decode_base64url_json_array(value: &str) -> Result<Vec<Value>, (Status, String)> {
    decode_base64url_json(value)?
        .as_array()
        .cloned()
        .ok_or((Status::Forbidden, "credential-json-invalid".into()))
}

fn verify_issuer_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), (Status, String)> {
    let key = JWK::from(Params::OKP(OctetParams {
        curve: "Ed25519".to_owned(),
        public_key: Base64urlUInt(public_key.to_vec()),
        private_key: None,
    }));
    tinycloud_auth::ssi::claims::jws::verify_bytes(Algorithm::EdDSA, message, &key, signature)
        .map_err(|_| (Status::Forbidden, "credential-signature-invalid".into()))
}

struct CurrentAllow {
    _decision_context_digest_hex: String,
    approved_capabilities: Vec<Value>,
}

struct CurrentAllowContext<'a> {
    challenge: &'a policy_v3_challenge::Model,
    policy_root: &'a TinyCloudDelegation,
    enforcement_root: &'a TinyCloudDelegation,
    policy_root_cid: &'a str,
    enforcement_root_cid: &'a str,
    node_did: &'a str,
    now: OffsetDateTime,
}

fn evaluate_current_allow(
    legacy_claim: Option<&Value>,
    presentation: &Value,
    context: &CurrentAllowContext<'_>,
) -> Result<CurrentAllow, (Status, String)> {
    let CurrentAllowContext {
        challenge,
        policy_root,
        enforcement_root,
        policy_root_cid,
        enforcement_root_cid,
        node_did,
        now,
    } = context;
    // The evaluator result is derived from the signed policy roots and the
    // challenge request.  A caller-supplied `decision: Allow` is not an
    // authority input: every requested capability must be present in both
    // independently signed root ceilings.
    let requested = challenge
        .requested_capabilities
        .as_array()
        .ok_or((Status::Forbidden, "requested-capabilities-invalid".into()))?;
    if requested.is_empty() {
        return Err((Status::Forbidden, "policy-evaluator-denied".into()));
    }
    let approved_attenuation = attenuation_for_policy_capabilities(requested)?;
    for root in [policy_root, enforcement_root] {
        let TinyCloudDelegation::Ucan(ucan) = root else {
            return Err((Status::Forbidden, "policy-root-invalid".into()));
        };
        let root_attenuation = serde_json::to_value(&ucan.payload().attenuation)
            .map_err(|_| (Status::Forbidden, "policy-root-invalid".into()))?;
        if !attenuation_contains(&root_attenuation, &approved_attenuation) {
            return Err((Status::Forbidden, "policy-evaluator-denied".into()));
        }
    }
    let mut capability_sources = vec![(presentation, "presentation-capabilities-mismatch")];
    if let Some(claim) = legacy_claim {
        capability_sources.push((claim, "claim-capabilities-mismatch"));
    }
    for (source, label) in capability_sources {
        let supplied = source
            .get("requestedCapabilities")
            .and_then(Value::as_array)
            .ok_or((Status::Forbidden, label.into()))?;
        if canonical_value_set(supplied) != canonical_value_set(requested) {
            return Err((Status::Forbidden, label.into()));
        }
    }
    let policy_digest = fact(policy_root, "policyDigestHex")
        .ok_or((Status::Forbidden, "sibling-root-mismatch".into()))?;
    let enforcer_did = fact(enforcement_root, "enforcerDid")
        .ok_or((Status::Forbidden, "sibling-root-mismatch".into()))?;
    let context = serde_json::json!({
        "policyCid": challenge.policy_cid,
        "policyDigestHex": policy_digest,
        "policyDelegationCid": policy_root_cid,
        "enforcementDelegationCid": enforcement_root_cid,
        "enforcerDid": enforcer_did,
        "nodeAudience": node_did,
        "recipientDid": challenge.recipient_did,
        "challengeId": challenge.challenge_id,
        "nonceHashHex": challenge.nonce_hash_hex,
        "claimDigestHex": legacy_claim.map(digest_value),
        "presentationDigestHex": digest_value(presentation),
        "evaluatedAt": format_time(*now),
    });
    Ok(CurrentAllow {
        _decision_context_digest_hex: digest_value(&context),
        approved_capabilities: requested.clone(),
    })
}
fn session_cid_from_bytes(bytes: &[u8]) -> String {
    hash(bytes).to_cid(0x55).to_string()
}

fn base32_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut output = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer = 0_u16;
    let mut bits = 0_u8;
    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            output.push(ALPHABET[((buffer >> (bits - 5)) & 0x1f) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        output.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    output
}
fn parse_time(value: &str) -> Result<OffsetDateTime, time::error::Parse> {
    OffsetDateTime::parse(value, &Rfc3339)
}
fn format_time(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).expect("RFC3339")
}
fn bad(error: impl std::fmt::Display) -> (Status, String) {
    (Status::BadRequest, error.to_string())
}
fn db_error(error: impl std::fmt::Display) -> (Status, String) {
    (Status::ServiceUnavailable, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::encode_config;
    use serde_json::json;
    use tinycloud_auth::authorization::HeaderEncode;
    use tinycloud_auth::ssi::{claims::jwt::NumericDate, dids::DIDURLBuf, ucan::Payload};
    use tinycloud_core::migrations::Migrator;
    use tinycloud_core::sea_orm::{Database, EntityTrait, TransactionTrait};
    use tinycloud_core::sea_orm_migration::MigratorTrait;

    fn policy_fixture() -> Value {
        let keypair = tinycloud_core::libp2p::identity::ed25519::Keypair::generate();
        let owner_did = tinycloud_core::keys::public_key_to_did_key(
            tinycloud_core::libp2p::identity::Keypair::from(keypair.clone()).public(),
        );
        let now = OffsetDateTime::now_utc() - Duration::seconds(1);
        let mut policy = json!({
            "schema": POLICY_V1_SCHEMA,
            "policyId": "policy-example",
            "ownerDid": owner_did,
            "createdAt": format_time(now),
            "expiresAt": format_time(now + Duration::seconds(300)),
            "contentSource": {"digestHex": "00"},
            "capabilityCeiling": [],
            "signature": {"suite": "Ed25519", "signerDid": "", "value": ""}
        });
        policy["signature"]["signerDid"] = policy["ownerDid"].clone();
        let mut digest_input = policy.clone();
        digest_input.as_object_mut().unwrap().remove("policyId");
        digest_input.as_object_mut().unwrap().remove("signature");
        let mut digest_preimage = POLICY_V1_SCHEMA.as_bytes().to_vec();
        digest_preimage.push(0);
        digest_preimage.extend_from_slice(&canonical_json_value(&digest_input));
        let policy_id = format!("pol_{}", base32_lower(&Sha256::digest(digest_preimage)));
        policy["policyId"] = Value::String(policy_id);
        let mut unsigned = policy.clone();
        unsigned.as_object_mut().unwrap().remove("policyId");
        unsigned.as_object_mut().unwrap().remove("signature");
        let mut signing_bytes = POLICY_V1_SCHEMA.as_bytes().to_vec();
        signing_bytes.extend_from_slice(b"\0");
        signing_bytes.extend_from_slice(&canonical_json_value(&unsigned));
        let signature = keypair.sign(&Sha256::digest(signing_bytes));
        policy["signature"]["value"] = Value::String(encode_config(signature, URL_SAFE_NO_PAD));
        policy
    }

    #[test]
    fn policy_cid_is_bound_to_the_full_canonical_document() {
        let policy = policy_fixture();
        let bytes = canonical_json_value(&policy);
        let cid = tinycloud_auth::ipld_core::cid::Cid::new_v1(
            0x55,
            tinycloud_auth::multihash_codetable::Code::Sha2_256.digest(&bytes),
        )
        .to_string();
        assert!(validate_policy_document(&policy, &bytes, &cid).is_ok());

        let mut altered = policy;
        altered["capabilityCeiling"] = json!(["tinycloud:read"]);
        let altered_bytes = canonical_json_value(&altered);
        assert!(validate_policy_document(&altered, &altered_bytes, &cid).is_err());
    }

    #[tokio::test]
    async fn policy_v2_admits_independently_issued_holder_evidence_with_distinct_principals(
    ) -> anyhow::Result<()> {
        use k256::ecdsa::SigningKey;
        use sha3::Keccak256;
        use tinycloud_auth::cacaos::siwe::encode_eip55;

        let vector: Value = serde_json::from_str(include_str!(
            "../test-fixtures/tc-470-policy-credential-requirement.json"
        ))
        .unwrap();
        let requirement = vector["sdkRequirement"].clone();
        let projection = vector["policyProjection"].clone();
        assert_eq!(
            canonical_digest_base64url(&requirement),
            vector["requirementDigest"]
        );

        let owner_key = tinycloud_core::libp2p::identity::ed25519::Keypair::generate();
        let issuer_key = tinycloud_core::libp2p::identity::ed25519::Keypair::generate();
        let holder_key = tinycloud_core::libp2p::identity::ed25519::Keypair::generate();
        let enforcer_key = tinycloud_core::libp2p::identity::ed25519::Keypair::generate();
        let did = |key: &tinycloud_core::libp2p::identity::ed25519::Keypair| {
            tinycloud_core::keys::public_key_to_did_key(
                tinycloud_core::libp2p::identity::Keypair::from(key.clone()).public(),
            )
        };
        let owner_did = did(&owner_key);
        let holder_did = did(&holder_key);
        let enforcer_did = did(&enforcer_key);
        let account_key = SigningKey::from_bytes(&[0x47; 32].into())?;
        let account_public = account_key.verifying_key().to_encoded_point(false);
        let account_digest = Keccak256::digest(&account_public.as_bytes()[1..]);
        let account_address: [u8; 20] = account_digest[12..].try_into()?;
        let account_owner_did = format!("did:pkh:eip155:1:0x{}", encode_eip55(&account_address));
        let credentials_space =
            SpaceId::new(account_owner_did.parse::<DIDBuf>()?, "credentials".parse()?);
        let content_space = SpaceId::new(owner_did.parse::<DIDBuf>()?, "applications".parse()?);
        let content_resource = content_space.clone().to_resource(
            "kv".parse()?,
            Some("shares/tc-470/document.txt".parse()?),
            None,
            None,
        );
        let node_secret = StaticSecret::new(vec![29; 32]).unwrap();
        let node_did = node_secret.node_did();
        let issuer_did = projection["issuerDid"].as_str().unwrap();
        let principals = [
            owner_did.as_str(),
            issuer_did,
            holder_did.as_str(),
            account_owner_did.as_str(),
            enforcer_did.as_str(),
            node_did.as_str(),
        ];
        for (index, principal) in principals.iter().enumerate() {
            assert!(!principals[..index].contains(principal));
        }
        assert_ne!(content_space, credentials_space);
        assert_eq!(content_space.did().as_str(), owner_did);
        assert_eq!(credentials_space.did().as_str(), account_owner_did);

        let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        let issued = now - Duration::seconds(5);
        let expires = now + Duration::seconds(600);
        let requested = vec![json!({
            "kind": "kv",
            "resource": content_resource.to_string(),
            "selector": "exact",
            "actions": ["tinycloud.kv/get"]
        })];
        let encryption_resource = format!("urn:tinycloud:encryption:{owner_did}:mainnet");
        let ceiling = vec![
            requested[0].clone(),
            json!({
                "kind": "encryption",
                "resource": encryption_resource,
                "action": "tinycloud.encryption/decrypt"
            }),
        ];
        let content_source = json!({
            "shareId": "share-tc-470",
            "kvResource": content_resource.to_string(),
            "selector": "exact",
            "encryptionNetwork": encryption_resource,
            "encryptedSymmetricKeyDigestHex": "aa".repeat(32),
            "keyVersion": 1,
            "mode": "immutable",
            "initialCiphertextDigestHex": "bb".repeat(32)
        });
        let mut policy = json!({
            "schema": POLICY_V2_SCHEMA,
            "policyId": "pending",
            "ownerDid": owner_did,
            "createdAt": format_time(issued),
            "expiresAt": format_time(expires),
            "contentSource": content_source,
            "capabilityCeiling": ceiling,
            "credentialRequirement": projection,
            "signature": {"suite": "Ed25519", "signerDid": owner_did, "value": ""}
        });
        let mut policy_unsigned = policy.clone();
        policy_unsigned.as_object_mut().unwrap().remove("policyId");
        policy_unsigned.as_object_mut().unwrap().remove("signature");
        let mut policy_preimage = POLICY_V2_SCHEMA.as_bytes().to_vec();
        policy_preimage.push(0);
        policy_preimage.extend_from_slice(&canonical_json_value(&policy_unsigned));
        policy["policyId"] = json!(format!(
            "pol_{}",
            base32_lower(&Sha256::digest(&policy_preimage))
        ));
        policy["signature"]["value"] = json!(encode_config(
            owner_key.sign(&Sha256::digest(policy_preimage)),
            URL_SAFE_NO_PAD
        ));
        let policy_bytes = canonical_json_value(&policy);
        let policy_cid = tinycloud_auth::ipld_core::cid::Cid::new_v1(
            0x55,
            tinycloud_auth::multihash_codetable::Code::Sha2_256.digest(&policy_bytes),
        )
        .to_string();
        validate_policy_document(&policy, &policy_bytes, &policy_cid).unwrap();

        let disclosure = encode_config(
            canonical_json_value(&json!(["salt-tc-470", "email", "alice@example.test"])),
            URL_SAFE_NO_PAD,
        );
        let payload = json!({
            "iss": issuer_did,
            "sub": holder_did,
            "iat": issued.unix_timestamp(),
            "nbf": issued.unix_timestamp(),
            "exp": expires.unix_timestamp(),
            "jti": "credential-tc-470",
            "vct": "opencredentials.email/v1",
            "profile": "tinycloud.email-proof/v1",
            "profileVersion": 1,
            "descriptorDigest": vector["policyProjection"]["descriptorDigest"],
            "holderBinding": {
                "did": holder_did,
                "signingDomain": "tinycloud.credentials/holder-binding/v1"
            },
            "_sd_alg": "sha-256",
            "_sd": [encode_config(Sha256::digest(disclosure.as_bytes()), URL_SAFE_NO_PAD)]
        });
        let header = json!({
            "alg": "EdDSA",
            "typ": "vc+sd-jwt",
            "kid": vector["policyProjection"]["issuerKid"]
        });
        let encoded_header = encode_config(canonical_json_value(&header), URL_SAFE_NO_PAD);
        let encoded_payload = encode_config(canonical_json_value(&payload), URL_SAFE_NO_PAD);
        let signing_input = format!("{encoded_header}.{encoded_payload}");
        let compact = format!(
            "{signing_input}.{}~{disclosure}",
            encode_config(issuer_key.sign(signing_input.as_bytes()), URL_SAFE_NO_PAD)
        );
        let claims = json!({"email": "alice@example.test"});
        let credential = json!({
            "type": "OpenCredentialsIssuedCredential",
            "version": 1,
            "protocol": "tinycloud.credentials/acquisition/v1",
            "profile": {"id": "tinycloud.email-proof/v1", "version": 1},
            "credentialType": {"id": "opencredentials.email/v1", "version": 1},
            "schema": "opencredentials.email/v1",
            "format": "vc+sd-jwt",
            "issuerDid": issuer_did,
            "issuerKid": vector["policyProjection"]["issuerKid"],
            "subjectDid": holder_did,
            "holderDid": holder_did,
            "claims": claims,
            "claimsDigest": canonical_digest_base64url(&claims),
            "descriptorDigest": vector["policyProjection"]["descriptorDigest"],
            "credentialId": "credential-tc-470",
            "issuedAt": format_time(issued),
            "notBefore": format_time(issued),
            "expiresAt": format_time(expires),
            "status": {"method": "none", "freshnessSeconds": 300},
            "credential": compact
        });
        let credential_digest = encode_config(
            Sha256::digest(credential["credential"].as_str().unwrap().as_bytes()),
            URL_SAFE_NO_PAD,
        );
        let challenge_id = "challenge-tc-470";
        let nonce = "nonce-tc-470";
        let mut presentation = json!({
            "schema": CREDENTIAL_PRESENTATION_V3_SCHEMA,
            "jti": "presentation-tc-470",
            "challengeId": challenge_id,
            "nonce": nonce,
            "policyCid": policy_cid,
            "nodeAudience": node_did,
            "holderDid": holder_did,
            "subjectDid": holder_did,
            "credentialSpaceOwnerDid": account_owner_did,
            "credentialDigest": credential_digest,
            "requirementDigest": vector["requirementDigest"],
            "descriptorDigest": vector["policyProjection"]["descriptorDigest"],
            "requestedCapabilities": requested,
            "issuedAt": format_time(now),
            "expiresAt": format_time(now + Duration::seconds(60)),
            "signature": {"suite": "Ed25519", "signerDid": holder_did, "value": ""}
        });
        let mut unsigned_presentation = presentation.clone();
        unsigned_presentation
            .as_object_mut()
            .unwrap()
            .remove("signature");
        let mut presentation_preimage = CREDENTIAL_PRESENTATION_V3_DOMAIN.to_vec();
        presentation_preimage.extend_from_slice(&canonical_json_value(&unsigned_presentation));
        presentation["signature"]["value"] = json!(encode_config(
            holder_key.sign(&Sha256::digest(presentation_preimage)),
            URL_SAFE_NO_PAD
        ));

        let issuer = IssuerKey::new(
            issuer_did,
            "opencredentials.email/v1",
            1,
            vector["policyProjection"]["issuerKid"].as_str().unwrap(),
            issuer_key.public().to_bytes(),
        );
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let runtime =
            PolicyV3Runtime::new(db.clone(), node_did, node_secret).with_credential_issuer(issuer);
        let admission = validate_credential_admission_v3(
            &requirement,
            &credential,
            &presentation,
            &policy,
            &ClaimPresentationContext {
                challenge_id,
                nonce,
                policy_cid: presentation["policyCid"].as_str().unwrap(),
                owner_did: policy["ownerDid"].as_str().unwrap(),
                recipient_did: holder_did.as_str(),
                authenticated_account_owner: Some(&account_owner_did),
                now,
            },
            &runtime,
            presentation["requestedCapabilities"].as_array().unwrap(),
        )
        .map_err(|(_, error)| anyhow::anyhow!(error))?;
        assert_eq!(admission.credential_id, "credential-tc-470");
        assert_eq!(admission.credential_space_owner_did, account_owner_did);

        let binding_material =
            json!({"enforcerDid": enforcer_did, "nodeAudience": runtime.node_did});
        let mut binding = json!({
            "schema": ATTESTED_ENFORCER_V2_SCHEMA,
            "enforcerDid": enforcer_did,
            "nodeAudience": runtime.node_did,
            "attestationBindingDigestHex": hex::encode(Sha256::digest(canonical_json_value(&binding_material))),
            "issuedAt": format_time(now),
            "expiresAt": format_time(now + Duration::seconds(60))
        });
        let mut binding_preimage = b"xyz.tinycloud.policy/AttestedEnforcerBinding/v2\0".to_vec();
        binding_preimage.extend_from_slice(&canonical_json_value(&binding));
        binding["signature"] = json!({
            "suite": "Ed25519",
            "signerDid": runtime.node_did,
            "value": encode_config(runtime.signer.node_keypair().sign(&Sha256::digest(binding_preimage)).unwrap(), URL_SAFE_NO_PAD)
        });
        validate_attested_enforcer_binding(
            &binding,
            enforcer_did.as_str(),
            runtime.node_did.as_str(),
            now + Duration::seconds(60),
            now,
        )
        .map_err(|(_, error)| anyhow::anyhow!(error))?;

        // Build the real sibling roots. Their authority is owner-signed, the
        // enforcement audience is deliberately distinct from Node, and the
        // ordinary attenuation is the same native TinyCloud KV resource that
        // the final `/invoke` reads.
        let projections =
            registration_projections(&policy).map_err(|(_, error)| anyhow::anyhow!(error))?;
        let owner_jwk = JWK::from(Params::OKP(OctetParams {
            curve: "Ed25519".to_owned(),
            public_key: Base64urlUInt(owner_key.public().to_bytes().to_vec()),
            private_key: Some(Base64urlUInt(owner_key.secret().as_ref().to_vec())),
        }));
        let owner_vm = format!("{owner_did}#{}", owner_did.trim_start_matches("did:key:"));
        let policy_digest =
            policy_digest_hex(&policy).map_err(|(_, error)| anyhow::anyhow!(error))?;
        let common_facts = json!({
            "ownerDid": owner_did,
            "policyId": policy["policyId"],
            "policyDigestHex": policy_digest,
            "policyCid": policy_cid,
            "contentSourceDigestHex": projections.content_source_digest_hex,
            "capabilityCeilingHashHex": projections.capability_ceiling_hash_hex,
            "nativeProjectionHashHex": projections.native_projection_hash_hex,
            "nodeAudience": runtime.node_did,
        });
        let root_payload = |audience: &str, role: &str, mode: &str, enforcer: Option<&str>| {
            let mut facts = common_facts.as_object().unwrap().clone();
            facts.insert("role".into(), json!(role));
            facts.insert("mode".into(), json!(mode));
            if let Some(enforcer) = enforcer {
                facts.insert("enforcerDid".into(), json!(enforcer));
            }
            Payload {
                issuer: owner_vm.parse::<DIDURLBuf>().unwrap(),
                audience: audience.parse::<DIDBuf>().unwrap(),
                not_before: Some(
                    NumericDate::try_from_seconds(issued.unix_timestamp() as f64).unwrap(),
                ),
                expiration: NumericDate::try_from_seconds(expires.unix_timestamp() as f64).unwrap(),
                nonce: Some(format!("tc-470-{role}")),
                facts: Some(vec![Value::Object(facts)]),
                proof: vec![],
                attenuation: serde_json::from_value(projections.attenuation.clone()).unwrap(),
            }
            .sign(Algorithm::EdDSA, &owner_jwk)
            .unwrap()
        };
        let policy_root_authorization = TinyCloudDelegation::Ucan(Box::new(root_payload(
            &format!("did:tinycloud:policy:{policy_digest}"),
            "policy-authority",
            "policy-source",
            None,
        )))
        .encode()?;
        let enforcement_root_authorization = TinyCloudDelegation::Ucan(Box::new(root_payload(
            &enforcer_did,
            "policy-enforcement",
            "conditional-mint",
            Some(&enforcer_did),
        )))
        .encode()?;

        use rocket::{http::ContentType, local::asynchronous::Client};
        use std::sync::Arc;
        use tinycloud_auth::{
            authorization::{make_invocation, InvocationOptions},
            cacaos::{
                siwe::{Message, Version},
                siwe_cacao::{Header as SiweHeader, Signature as SiweSignature, SiweCacao},
            },
            siwe_recap::{Ability as RecapAbility, Capability as RecapCapability},
            ucan_capabilities_object::Capabilities,
        };
        use tinycloud_core::{
            database_artifacts::SeaOrmDatabaseArtifactRepository,
            encryption::ColumnEncryption,
            encryption_network::{EncryptionService, LocalOneOfOneBackend},
            sql::SqlService,
            storage::{either::Either, StorageConfig as _},
        };

        let storage_dir = tempfile::TempDir::new()?;
        let storage = crate::storage::file_system::FileSystemConfig::new(storage_dir.path())
            .open()
            .await?;
        let _storage_dir = storage_dir.keep();
        let tinycloud = crate::TinyCloud::new(
            db.clone(),
            Either::B(storage),
            StaticSecret::new(vec![0; 32]).map_err(|_| anyhow::anyhow!("invalid secret"))?,
        )
        .await?;
        let sql_dir = tempfile::TempDir::new()?;
        let sql_path = sql_dir.path().to_string_lossy().to_string();
        let _sql_dir = sql_dir.keep();
        let sql_service = SqlService::new(
            sql_path,
            u64::MAX,
            Arc::new(SeaOrmDatabaseArtifactRepository::new(db.clone())),
        );
        let encryption_backend = Arc::new(LocalOneOfOneBackend::new(ColumnEncryption::new(
            runtime
                .signer
                .derive_key(b"tinycloud/encryption/network-seal"),
        )));
        let encryption = EncryptionService::new_with_node_keypair(
            db.clone(),
            runtime.signer.node_keypair(),
            encryption_backend,
        );
        let rocket = rocket::build()
            .mount(
                "/",
                rocket::routes![
                    register_policy,
                    issue_enforcer_binding,
                    challenge,
                    mint,
                    crate::routes::delegate,
                    crate::routes::invoke
                ],
            )
            .attach(crate::tracing::TracingFairing::new(
                &crate::config::Config::default().log.tracing,
            ))
            .manage(tinycloud)
            .manage(runtime.clone())
            .manage(sql_service)
            .manage(crate::config::Config::default())
            .manage(crate::quota::QuotaCache::new(None, None))
            .manage(crate::invocation_replay::InvocationReplayCache::new(
                db.clone(),
            ))
            .manage(crate::hooks::HookRuntime::new(
                crate::config::HooksConfig::default(),
                [31; 32],
            ))
            .manage(crate::BlockStage::from(
                crate::config::StagingStorage::Memory,
            ))
            .manage(encryption);
        let client = Client::tracked(rocket).await?;

        // The sender independently hosts and writes the sender-owned content
        // space through the ordinary graph. The recipient account proof below
        // never carries authority for this resource.
        let mut sender_capabilities = Capabilities::<Value>::new();
        sender_capabilities.with_action(
            content_space
                .clone()
                .to_resource("space".parse()?, None, None, None)
                .as_uri(),
            "tinycloud.space/host".parse::<RecapAbility>()?,
            [std::collections::BTreeMap::<String, Value>::new()],
        );
        sender_capabilities.with_action(
            content_resource.as_uri(),
            "tinycloud.kv/put".parse::<RecapAbility>()?,
            [std::collections::BTreeMap::<String, Value>::new()],
        );
        let sender_authorization = TinyCloudDelegation::Ucan(Box::new(
            Payload {
                issuer: owner_vm.parse()?,
                audience: holder_did.parse()?,
                not_before: Some(NumericDate::try_from_seconds(
                    issued.unix_timestamp() as f64
                )?),
                expiration: NumericDate::try_from_seconds(expires.unix_timestamp() as f64)?,
                nonce: Some("tc470-sender-content".into()),
                facts: Some(vec![]),
                proof: vec![],
                attenuation: sender_capabilities,
            }
            .sign(Algorithm::EdDSA, &owner_jwk)?,
        ))
        .encode()?;
        let sender_response = client
            .post("/delegate")
            .header(rocket::http::Header::new(
                "Authorization",
                sender_authorization,
            ))
            .dispatch()
            .await;
        let sender_status = sender_response.status();
        let sender_body = sender_response.into_string().await.unwrap_or_default();
        assert_eq!(sender_status, Status::Ok, "sender /delegate: {sender_body}");
        let sender_cid = serde_json::from_str::<Value>(&sender_body)?["cid"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing sender delegation cid"))?
            .parse()?;

        // Import the recipient's existing SDK account-session CACAO through
        // the real ordinary `/delegate` route. Its only signed authority is
        // the exact durable credential namespace used by the Web SDK.
        let mut recap = RecapCapability::<Value>::new();
        let credential_namespace =
            credentials_space
                .clone()
                .to_resource("kv".parse()?, Some("v1/".parse()?), None, None);
        for ability in ["tinycloud.kv/get", "tinycloud.kv/put"] {
            recap.with_action(
                credential_namespace.as_uri(),
                ability.parse::<RecapAbility>()?,
                [std::collections::BTreeMap::<String, Value>::new()],
            );
        }
        let account_message = recap.build_message(Message {
            scheme: Some("https".parse()?),
            domain: "tc470.test".parse()?,
            address: account_address,
            statement: None,
            uri: holder_did.parse()?,
            version: Version::V1,
            chain_id: 1,
            nonce: "tc470-account-session".into(),
            issued_at: issued.into(),
            expiration_time: Some(expires.into()),
            not_before: None,
            request_id: None,
            resources: vec![],
        })?;
        let (account_signature, recovery_id) =
            account_key.sign_prehash_recoverable(&account_message.eip191_hash()?)?;
        let mut account_signature_bytes = [0_u8; 65];
        account_signature_bytes[..64].copy_from_slice(account_signature.to_bytes().as_ref());
        account_signature_bytes[64] = u8::from(recovery_id) + 27;
        let account_authorization = TinyCloudDelegation::Cacao(Box::new(SiweCacao::new(
            account_message.into(),
            SiweSignature::from(account_signature_bytes),
            SiweHeader,
        )))
        .encode()?;
        let account_response = client
            .post("/delegate")
            .header(rocket::http::Header::new(
                "Authorization",
                account_authorization,
            ))
            .dispatch()
            .await;
        let account_status = account_response.status();
        let account_body = account_response.into_string().await.unwrap_or_default();
        assert_eq!(
            account_status,
            Status::Ok,
            "account /delegate: {account_body}"
        );
        let account_cid: tinycloud_auth::ipld_core::cid::Cid =
            serde_json::from_str::<Value>(&account_body)?["cid"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing account delegation cid"))?
                .parse()?;
        let (_, stored_account) = client
            .rocket()
            .state::<crate::TinyCloud>()
            .unwrap()
            .load_signed_delegation(account_cid)
            .await
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| anyhow::anyhow!("missing stored account authorization"))?;
        assert!(matches!(
            stored_account.0.delegation,
            TinyCloudDelegation::Cacao(_)
        ));
        space::ActiveModel {
            id: Set(SpaceIdWrap(credentials_space.clone())),
        }
        .insert(&client.rocket().state::<PolicyV3Runtime>().unwrap().conn)
        .await?;

        // Seed a real object via the ordinary data plane so the final read
        // proves authorization and content access rather than only admission.
        let mut holder_jwk = JWK::from(Params::OKP(OctetParams {
            curve: "Ed25519".to_owned(),
            public_key: Base64urlUInt(holder_key.public().to_bytes().to_vec()),
            private_key: Some(Base64urlUInt(holder_key.secret().as_ref().to_vec())),
        }));
        holder_jwk.algorithm = Some(Algorithm::EdDSA);
        let holder_vm = format!("{holder_did}#{}", holder_did.trim_start_matches("did:key:"));
        let seed = make_invocation(
            [(
                content_resource.clone(),
                ["tinycloud.kv/put".parse::<RecapAbility>()?],
            )],
            &sender_cid,
            &holder_jwk,
            &holder_vm,
            (OffsetDateTime::now_utc() + Duration::seconds(45)).unix_timestamp() as f64,
            InvocationOptions {
                nonce: Some("tc470-seed-content".into()),
                ..InvocationOptions::default()
            },
        )?;
        let seed_response = client
            .post("/invoke")
            .header(rocket::http::Header::new("Authorization", seed.encode()?))
            .header(ContentType::Plain)
            .body("tc-470-real-content")
            .dispatch()
            .await;
        assert_eq!(seed_response.status(), Status::Ok);

        let binding_response = client
            .post("/share/v3/enforcer-bindings")
            .header(ContentType::JSON)
            .body(
                json!({
                    "rootExpiresAt": format_time(expires),
                    "enforcerDid": enforcer_did,
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(binding_response.status(), Status::Ok);
        let live_binding: Value = binding_response.into_json().await.unwrap();

        let register_response = client
            .post("/share/v3/policies")
            .header(ContentType::JSON)
            .body(
                json!({
                    "policyCid": policy_cid,
                    "policy": policy,
                    "policyRoot": policy_root_authorization,
                    "enforcementRoot": enforcement_root_authorization,
                    "contentSourceDigestHex": projections.content_source_digest_hex,
                    "nativeProjectionHashHex": projections.native_projection_hash_hex,
                    "attestedEnforcerBinding": live_binding,
                })
                .to_string(),
            )
            .dispatch()
            .await;
        let register_status = register_response.status();
        let register_body = register_response.into_string().await.unwrap_or_default();
        assert_eq!(register_status, Status::Ok, "register: {register_body}");

        let challenge_response = client
            .post("/share/v3/policy/challenges")
            .header(ContentType::JSON)
            .body(
                json!({
                    "policyCid": policy_cid,
                    "recipientDid": holder_did,
                    "requestedCapabilities": requested,
                })
                .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(challenge_response.status(), Status::Ok);
        let challenge_value: Value = challenge_response.into_json().await.unwrap();
        let challenge_id = challenge_value["challengeId"].as_str().unwrap();
        let nonce = challenge_value["nonce"].as_str().unwrap();

        // Rebind the real issuer-signed SD-JWT presentation to the live
        // challenge. The complete requirement and credential remain local to
        // this one mint request.
        presentation["challengeId"] = json!(challenge_id);
        presentation["nonce"] = json!(nonce);
        presentation["jti"] = json!("presentation-tc-470-http");
        presentation["issuedAt"] = json!(format_time(OffsetDateTime::now_utc()));
        presentation["expiresAt"] = json!(format_time(
            OffsetDateTime::now_utc() + Duration::seconds(45)
        ));
        let mut unsigned_presentation = presentation.clone();
        unsigned_presentation
            .as_object_mut()
            .unwrap()
            .remove("signature");
        let mut presentation_preimage = CREDENTIAL_PRESENTATION_V3_DOMAIN.to_vec();
        presentation_preimage.extend_from_slice(&canonical_json_value(&unsigned_presentation));
        presentation["signature"]["value"] = json!(encode_config(
            holder_key.sign(&Sha256::digest(presentation_preimage)),
            URL_SAFE_NO_PAD
        ));
        let mint_response = client
            .post("/share/v3/policy/delegations")
            .header(ContentType::JSON)
            .body(
                json!({
                    "policyCid": policy_cid,
                    "challengeId": challenge_id,
                    "nonce": nonce,
                    "requirement": requirement,
                    "credential": credential,
                    "accountAuthorizationCid": account_cid.to_string(),
                    "credentialSpaceId": credentials_space.to_string(),
                    "presentation": presentation,
                })
                .to_string(),
            )
            .dispatch()
            .await;
        let mint_status = mint_response.status();
        let mint_body = mint_response.into_string().await.unwrap_or_default();
        assert_eq!(mint_status, Status::Ok, "mint: {mint_body}");
        let minted: Value = serde_json::from_str(&mint_body)?;
        let s0_authorization = minted["authorization"].as_str().unwrap();
        for segment in s0_authorization.split('.').take(2) {
            let bytes = decode_config(segment, URL_SAFE_NO_PAD)?;
            let value: Value = serde_json::from_slice(&bytes)?;
            assert_eq!(bytes, canonical_json_value(&value));
        }
        let s0 =
            decode_delegation(s0_authorization).map_err(|(_, error)| anyhow::anyhow!(error))?;

        // Holder redelegates S0 through the production `/delegate` route.
        // Preserve the authenticated facts, narrow depth/time, and use a
        // fresh reader key so `/invoke` must traverse the ordinary graph.
        let reader_jwk = JWK::generate_ed25519()?;
        let reader_did = tinycloud_auth::resolver::DID_METHODS
            .generate(&reader_jwk, "key")?
            .to_string();
        let mut child_facts = match &s0.0.delegation {
            TinyCloudDelegation::Ucan(ucan) => ucan.payload().facts.clone().unwrap(),
            TinyCloudDelegation::Cacao(_) => unreachable!(),
        };
        child_facts[0]["remainingRedelegationDepth"] = json!(7);
        let child_not_before = s0.0.not_before.unwrap() + Duration::milliseconds(1);
        let child_expiry = s0.0.expiry.unwrap() - Duration::seconds(1);
        let child = Payload {
            issuer: holder_vm.parse()?,
            audience: reader_did.parse()?,
            not_before: Some(NumericDate::try_from_seconds(
                child_not_before.unix_timestamp_nanos() as f64 / 1_000_000_000.0,
            )?),
            expiration: NumericDate::try_from_seconds(
                child_expiry.unix_timestamp_nanos() as f64 / 1_000_000_000.0,
            )?,
            nonce: Some("tc470-policy-child".into()),
            facts: Some(child_facts),
            proof: vec![s0.content_hash().to_cid(0x55)],
            attenuation: serde_json::from_value::<Capabilities<Value>>(
                attenuation_for_policy_capabilities(&requested)
                    .map_err(|(_, error)| anyhow::anyhow!(error))?,
            )?,
        }
        .sign(Algorithm::EdDSA, &holder_jwk)?;
        let child_authorization = TinyCloudDelegation::Ucan(Box::new(child)).encode()?;
        let child_response = client
            .post("/delegate")
            .header(rocket::http::Header::new(
                "Authorization",
                child_authorization,
            ))
            .dispatch()
            .await;
        let child_status = child_response.status();
        let child_body = child_response.into_string().await.unwrap_or_default();
        assert_eq!(
            child_status,
            Status::Ok,
            "policy child /delegate: {child_body}"
        );
        let child_cid = serde_json::from_str::<Value>(&child_body)?["cid"]
            .as_str()
            .unwrap()
            .parse()?;

        let mut reader_vm = reader_did.clone();
        reader_vm.push('#');
        reader_vm.push_str(reader_did.trim_start_matches("did:key:"));
        let invocation_now = OffsetDateTime::now_utc();
        let read = Payload {
            issuer: reader_vm.parse()?,
            audience: reader_did.parse()?,
            not_before: Some(NumericDate::try_from_seconds(
                invocation_now.unix_timestamp() as f64,
            )?),
            expiration: NumericDate::try_from_seconds(
                (invocation_now + Duration::seconds(30)).unix_timestamp() as f64,
            )?,
            nonce: Some("tc470-policy-read".into()),
            facts: Some(Vec::<Value>::new()),
            proof: vec![child_cid],
            attenuation: serde_json::from_value::<Capabilities<Value>>(
                attenuation_for_policy_capabilities(&requested)
                    .map_err(|(_, error)| anyhow::anyhow!(error))?,
            )?,
        }
        .sign(Algorithm::EdDSA, &reader_jwk)?;
        let read_response = client
            .post("/invoke")
            .header(rocket::http::Header::new("Authorization", read.encode()?))
            .dispatch()
            .await;
        let read_status = read_response.status();
        let read_body = read_response.into_bytes().await.unwrap_or_default();
        assert_eq!(read_status, Status::Ok, "read response: {read_body:?}");
        assert_eq!(read_body, b"tc-470-real-content");
        Ok(())
    }

    #[test]
    fn v3_profile_and_cutoff_constants_are_stable() {
        assert_eq!(POLICY_SESSION_PROFILE, "policy-session-ucan/v1");
        assert!(LAST_V2_CREATE_AT < MAX_LEGACY_ENVELOPE_EXPIRES_AT);
        assert!(MAX_LEGACY_ENVELOPE_EXPIRES_AT < LAST_V2_READ_AT);
    }

    #[test]
    fn prefix_capability_containment_is_segment_bounded_at_every_boundary() {
        let root = "tinycloud://applications/kv/shares/root";
        let ceiling = vec![json!({
            "kind": "kv",
            "resource": root,
            "selector": "prefix",
            "actions": ["tinycloud.kv/get", "tinycloud.kv/list"]
        })];
        let child = json!({
            "kind": "kv",
            "resource": format!("{root}/folder/document.txt"),
            "selector": "exact",
            "actions": ["tinycloud.kv/get"]
        });
        assert!(
            validate_requested_policy_capabilities(std::slice::from_ref(&child), &ceiling).is_ok()
        );
        for mutation in [
            json!({"kind":"kv","resource":format!("{root}-sibling"),"selector":"exact","actions":["tinycloud.kv/get"]}),
            json!({"kind":"kv","resource":format!("{root}/folder/document.txt"),"selector":"exact","actions":["tinycloud.kv/put"]}),
        ] {
            assert!(validate_requested_policy_capabilities(&[mutation], &ceiling).is_err());
        }

        let parent = attenuation_for_policy_capabilities(&ceiling).unwrap();
        let exact_same = attenuation_for_policy_capabilities(&[json!({
            "kind":"kv","resource":root,"selector":"exact","actions":["tinycloud.kv/get"]
        })])
        .unwrap();
        let descendant = attenuation_for_policy_capabilities(&[child]).unwrap();
        let sibling = attenuation_for_policy_capabilities(&[json!({
            "kind":"kv","resource":format!("{root}-sibling"),"selector":"exact","actions":["tinycloud.kv/get"]
        })]).unwrap();
        assert!(attenuation_contains(&parent, &exact_same));
        assert!(attenuation_contains(&parent, &descendant));
        assert!(!attenuation_contains(&parent, &sibling));
    }

    #[test]
    fn mint_rejects_caller_supplied_authority() {
        assert!(serde_json::from_value::<MintRequest>(json!({
            "policyCid": "bafy-policy",
            "challengeId": "challenge",
            "authorization": "caller-controlled",
            "nonce": "nonce"
        }))
        .is_err());
    }

    #[tokio::test]
    async fn compact_cross_language_authorizations_are_exact_node_ucans() {
        let vector: Value = serde_json::from_str(include_str!(
            "../test-fixtures/tc-405-compact-authorization.json"
        ))
        .unwrap();
        let policy = vector["policy"]["value"].clone();
        let projections = registration_projections(&policy).unwrap();
        assert_eq!(
            projections.content_source_digest_hex,
            vector["projections"]["contentSourceDigestHex"]
        );
        assert_eq!(
            projections.capability_ceiling_hash_hex,
            vector["projections"]["capabilityCeilingHashHex"]
        );
        assert_eq!(
            projections.native_projection_hash_hex,
            vector["projections"]["nativeProjectionHashHex"]
        );
        let request = RegisterRequest {
            policy_cid: vector["policy"]["policyCid"].as_str().unwrap().to_owned(),
            policy,
            policy_root: vector["policyRoot"]["authorization"]
                .as_str()
                .unwrap()
                .to_owned(),
            enforcement_root: vector["enforcementRoot"]["authorization"]
                .as_str()
                .unwrap()
                .to_owned(),
            content_source_digest_hex: projections.content_source_digest_hex.clone(),
            native_projection_hash_hex: projections.native_projection_hash_hex.clone(),
            attested_enforcer_binding: Value::Null,
        };
        let (policy_cid, policy_root) = decode_root(&request.policy_root).unwrap();
        let (enforcement_cid, enforcement_root) = decode_root(&request.enforcement_root).unwrap();
        assert_eq!(policy_cid, vector["policyRoot"]["cid"]);
        assert_eq!(enforcement_cid, vector["enforcementRoot"]["cid"]);
        assert_eq!(
            policy_root.serialized_bytes(),
            request.policy_root.as_bytes()
        );
        assert_eq!(
            enforcement_root.serialized_bytes(),
            request.enforcement_root.as_bytes()
        );
        for root in [&policy_root.0.delegation, &enforcement_root.0.delegation] {
            let TinyCloudDelegation::Ucan(ucan) = root else {
                panic!("vector root must be UCAN");
            };
            ucan.verify_signature(&AnyDidMethod::default())
                .await
                .unwrap();
        }
        validate_root_pair(
            &request,
            &policy_root.0,
            &enforcement_root.0,
            vector["principals"]["nodeDid"].as_str().unwrap(),
            &projections,
        )
        .unwrap();

        let s0 = decode_delegation(vector["s0"]["authorization"].as_str().unwrap()).unwrap();
        assert_eq!(
            s0.content_hash().to_cid(0x55).to_string(),
            vector["s0"]["cid"]
        );
        assert_eq!(
            s0.0.parents
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec![policy_cid, enforcement_cid]
        );
        let s1 = decode_delegation(vector["s1"]["authorization"].as_str().unwrap()).unwrap();
        let s2 = decode_delegation(vector["s2"]["authorization"].as_str().unwrap()).unwrap();
        assert_eq!(
            s1.content_hash().to_cid(0x55).to_string(),
            vector["s1"]["cid"]
        );
        assert_eq!(
            s2.content_hash().to_cid(0x55).to_string(),
            vector["s2"]["cid"]
        );
        assert_eq!(s1.0.parents[0].to_string(), vector["s0"]["cid"]);
        assert_eq!(s2.0.parents[0].to_string(), vector["s1"]["cid"]);
        assert!(descendant_time_is_narrower(&s1.0, &s0.0));
        assert!(descendant_time_is_narrower(&s2.0, &s1.0));
        assert!(descendant_profile_is_inherited(&s1.0, &s0.0));
        assert!(descendant_profile_is_inherited(&s2.0, &s1.0));
        for descendant in [&s0.0.delegation, &s1.0.delegation, &s2.0.delegation] {
            let TinyCloudDelegation::Ucan(ucan) = descendant else {
                panic!("vector descendant must be UCAN");
            };
            ucan.verify_signature(&AnyDidMethod::default())
                .await
                .unwrap();
        }
    }

    #[test]
    fn registration_recomputes_and_rejects_projection_mutations() {
        let vector: Value = serde_json::from_str(include_str!(
            "../test-fixtures/tc-405-compact-authorization.json"
        ))
        .unwrap();
        let mut policy = vector["policy"]["value"].clone();
        let original = registration_projections(&policy).unwrap();
        policy["contentSource"]["keyVersion"] = json!(2);
        let changed = registration_projections(&policy).unwrap();
        assert_ne!(
            original.content_source_digest_hex,
            changed.content_source_digest_hex
        );
        policy = vector["policy"]["value"].clone();
        policy["capabilityCeiling"][0]["actions"] = json!(["tinycloud.kv/get"]);
        let changed = registration_projections(&policy).unwrap();
        assert_ne!(
            original.capability_ceiling_hash_hex,
            changed.capability_ceiling_hash_hex
        );
        assert_ne!(
            original.native_projection_hash_hex,
            changed.native_projection_hash_hex
        );
    }

    #[tokio::test]
    async fn challenge_and_session_rows_roll_back_together_and_jti_is_unique() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        policy_v3_challenge::ActiveModel {
            challenge_id: Set("challenge-rollback".into()),
            policy_cid: Set("policy".into()),
            recipient_did: Set("did:key:recipient".into()),
            nonce_hash_hex: Set("00".repeat(32)),
            requested_capabilities: Set(json!([{"kind":"encryption","resource":"urn:tinycloud:encryption:did:key:owner:mainnet","action":"tinycloud.encryption/decrypt"}])),
            issued_at: Set("2026-07-31T12:00:00Z".into()),
            expires_at: Set("2026-07-31T12:05:00Z".into()),
            consumed_at: Set(None),
        }
        .insert(&db)
        .await
        .unwrap();

        let tx = db.begin().await.unwrap();
        policy_v3_challenge::Entity::update_many()
            .col_expr(
                policy_v3_challenge::Column::ConsumedAt,
                Expr::value("2026-07-31T12:00:01Z"),
            )
            .filter(policy_v3_challenge::Column::ChallengeId.eq("challenge-rollback"))
            .exec(&tx)
            .await
            .unwrap();
        test_session("session-rolled-back", "jti-once")
            .insert(&tx)
            .await
            .unwrap();
        tx.rollback().await.unwrap();

        assert!(
            policy_v3_challenge::Entity::find_by_id("challenge-rollback")
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .consumed_at
                .is_none()
        );
        assert!(policy_v3_session::Entity::find_by_id("session-rolled-back")
            .one(&db)
            .await
            .unwrap()
            .is_none());

        test_session("session-first", "jti-once")
            .insert(&db)
            .await
            .unwrap();
        assert!(test_session("session-second", "jti-once")
            .insert(&db)
            .await
            .is_err());
    }

    fn test_session(cid: &str, claim_jti: &str) -> policy_v3_session::ActiveModel {
        policy_v3_session::ActiveModel {
            session_cid: Set(cid.into()),
            policy_cid: Set("policy".into()),
            authorization_bytes: Set(cid.as_bytes().to_vec()),
            recipient_did: Set("did:key:recipient".into()),
            claim_jti: Set(claim_jti.into()),
            claim_digest_hex: Set("11".repeat(32)),
            vp_digest_hex: Set("22".repeat(32)),
            state: Set("admitted".into()),
            not_before: Set("2026-07-31T12:00:00Z".into()),
            expires_at: Set("2026-07-31T12:01:00Z".into()),
            admitted_at: Set(Some("2026-07-31T12:00:00Z".into())),
        }
    }

    #[tokio::test]
    async fn signed_descendant_tampering_and_proof_reordering_fail_verification() {
        let vector: Value = serde_json::from_str(include_str!(
            "../test-fixtures/tc-405-compact-authorization.json"
        ))
        .unwrap();
        let authorization = vector["s0"]["authorization"].as_str().unwrap();
        let mut parts = authorization
            .split('.')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let payload_bytes = decode_config(&parts[1], URL_SAFE_NO_PAD).unwrap();
        let mut payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
        payload["prf"].as_array_mut().unwrap().swap(0, 1);
        parts[1] = encode_config(canonical_json_value(&payload), URL_SAFE_NO_PAD);
        let reordered = parts.join(".");
        let event = decode_delegation(&reordered).unwrap();
        let TinyCloudDelegation::Ucan(ucan) = &event.0.delegation else {
            panic!("fixture must remain UCAN");
        };
        assert!(ucan
            .verify_signature(&AnyDidMethod::default())
            .await
            .is_err());

        let s0 = decode_delegation(authorization).unwrap();
        let s1 = decode_delegation(vector["s1"]["authorization"].as_str().unwrap()).unwrap();
        let s2 = decode_delegation(vector["s2"]["authorization"].as_str().unwrap()).unwrap();
        assert!(capabilities_are_contained(
            &s1.0.capabilities,
            &s0.0.capabilities
        ));
        assert!(capabilities_are_contained(
            &s2.0.capabilities,
            &s1.0.capabilities
        ));
        assert!(descendant_profile_is_inherited(&s1.0, &s0.0));
        assert!(descendant_profile_is_inherited(&s2.0, &s1.0));
    }

    #[tokio::test]
    async fn registered_sibling_roots_are_never_ordinary_parent_authority() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        policy_v3_root::ActiveModel {
            root_cid: Set("bafy-enforcement-root".into()),
            policy_cid: Set("bafy-policy".into()),
            role: Set("policy-enforcement".into()),
            authorization_bytes: Set(b"signed-root".to_vec()),
            status_checkpoint_bytes: Set(None),
            previous_checkpoint_digest_hex: Set(None),
            status_sequence: Set(1),
            admission_epoch: Set(0),
            status_checked_at: Set(None),
            status_fresh_until: Set(None),
            revoked_at: Set(None),
            revocation_bytes: Set(None),
        }
        .insert(&db)
        .await
        .unwrap();
        let runtime =
            PolicyV3Runtime::new(db, "did:key:zNode", StaticSecret::new(vec![7; 32]).unwrap());
        assert!(runtime
            .is_registered_policy_root("bafy-enforcement-root")
            .await
            .unwrap());
        assert!(!runtime
            .is_registered_policy_root("bafy-ordinary-parent")
            .await
            .unwrap());
    }

    #[test]
    fn golden_checkpoint_and_revocation_bytes_verify_and_tampering_fails() {
        let vector: Value = serde_json::from_str(include_str!(
            "../test-fixtures/tc-405-compact-authorization.json"
        ))
        .unwrap();
        let node = vector["principals"]["nodeDid"].as_str().unwrap();
        let owner = vector["principals"]["ownerDid"].as_str().unwrap();
        let enforcer = vector["principals"]["enforcerDid"].as_str().unwrap();
        let checkpoint = &vector["checkpoint"]["value"];
        verify_signed_json(checkpoint, STATUS_DOMAIN, node).unwrap();

        let revocation = &vector["revocation"]["value"];
        let target = revocation["targetCid"].as_str().unwrap();
        let (_, digest, _) = validate_root_revocation(
            revocation,
            target,
            "policy-enforcement",
            owner,
            Some(enforcer),
            node,
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        assert_eq!(digest, vector["revocation"]["signatureDigestHex"]);

        let mut tampered = revocation.clone();
        tampered["reason"] = json!("substituted");
        assert!(validate_root_revocation(
            &tampered,
            target,
            "policy-enforcement",
            owner,
            Some(enforcer),
            node,
            OffsetDateTime::now_utc(),
        )
        .is_err());
    }
}
