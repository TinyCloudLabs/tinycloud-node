//! Encryption network service.
//!
//! Owns: network lifecycle, ceremony state, key backend access, decrypt
//! invocation verification, audit and nonce protection.
//!
//! Non-goals (v1): payload encryption API, envelope CRUD, plaintext payload
//! handling, recipient-list authorization.

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, DbErr, EntityTrait,
    QueryFilter,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::hash::hash;
use crate::keys::{public_key_to_did_key, Keypair, PublicKey};
use crate::models::{
    encryption_audit, encryption_ceremony, encryption_network, encryption_network_member,
    encryption_nonce,
};
use crate::util::InvocationInfo;

use super::backend::{KeyBackend, KeyBackendError};
use super::canonical::{canonical_hash, canonical_json_bytes, hash_hex};
use super::network_id::NetworkId;
use super::protocol::{
    DecryptFacts, DecryptInvocation, DecryptRequestBody, DecryptResponseBody, NetworkAdminFacts,
    NetworkAdminInvocation, DECRYPT_ACTION, DECRYPT_REQUEST_TYPE, DECRYPT_RESULT_TYPE,
    NETWORK_ADMIN_TYPE,
};
use super::types::{
    KeyBackendKind, NetworkDescriptor, NetworkMemberDescriptor, NetworkState, Threshold,
};

const DEFAULT_INVOCATION_TTL_SECONDS: i64 = 300;

#[derive(Debug, Error)]
pub enum EncryptionServiceError {
    #[error("db error: {0}")]
    Db(#[from] DbErr),
    #[error("network not found")]
    NetworkNotFound,
    #[error("network already exists")]
    NetworkAlreadyExists,
    #[error("network is not active (state: {0})")]
    NetworkNotActive(String),
    #[error("network has been revoked")]
    NetworkRevoked,
    #[error("decrypt action not permitted")]
    Unauthorized,
    #[error("invocation audience does not match this node")]
    AudienceMismatch,
    #[error("invocation target node does not match this node")]
    TargetNodeMismatch,
    #[error("invocation root principal does not match network principal")]
    PrincipalMismatch,
    #[error("invocation references a different network")]
    NetworkMismatch,
    #[error("invocation expired")]
    Expired,
    #[error("invocation not yet valid")]
    NotYetValid,
    #[error("invocation hash mismatch: {0}")]
    HashMismatch(&'static str),
    #[error("invocation alg / key version does not match network")]
    AlgKeyVersionMismatch,
    #[error("invocation signature is invalid: {0}")]
    SignatureInvalid(String),
    #[error("invocation type is not a decrypt invocation")]
    WrongInvocationType,
    #[error("nonce already used")]
    NonceReplay,
    #[error("key backend error: {0}")]
    Backend(#[from] KeyBackendError),
    #[error("decrypt request body is malformed: {0}")]
    InvalidBody(String),
    #[error("hex decode error: {0}")]
    Base64(&'static str),
    #[error("node response signing failed: {0}")]
    Signing(String),
}

pub struct EncryptionService {
    db: DatabaseConnection,
    node_did: String,
    node_keypair: Option<Keypair>,
    backend: Arc<dyn KeyBackend>,
    invocation_ttl_seconds: i64,
}

#[derive(Debug, Clone)]
pub struct CreateNetworkRequest {
    pub name: String,
    pub principal: String,
    pub threshold: Threshold,
}

#[derive(Debug, Clone)]
pub struct VerifiedDecrypt {
    pub response: DecryptResponseBody,
    pub request_hash: String,
}

impl EncryptionService {
    pub fn new(db: DatabaseConnection, node_did: String, backend: Arc<dyn KeyBackend>) -> Self {
        Self {
            db,
            node_did,
            node_keypair: None,
            backend,
            invocation_ttl_seconds: DEFAULT_INVOCATION_TTL_SECONDS,
        }
    }

    pub fn new_with_node_keypair(
        db: DatabaseConnection,
        node_keypair: Keypair,
        backend: Arc<dyn KeyBackend>,
    ) -> Self {
        let node_did = public_key_to_did_key(node_keypair.public());
        Self {
            db,
            node_did,
            node_keypair: Some(node_keypair),
            backend,
            invocation_ttl_seconds: DEFAULT_INVOCATION_TTL_SECONDS,
        }
    }

    pub fn node_did(&self) -> &str {
        &self.node_did
    }

    pub fn backend_kind(&self) -> KeyBackendKind {
        self.backend.kind()
    }

    /// Create a new network and complete a one-of-one ceremony in a single
    /// step. The resulting network is `Active`.
    pub async fn create_one_of_one_network(
        &self,
        req: CreateNetworkRequest,
    ) -> Result<NetworkDescriptor, EncryptionServiceError> {
        let network_id = NetworkId::new(req.principal.clone(), req.name.clone())
            .map_err(|e| EncryptionServiceError::InvalidBody(format!("invalid network id: {e}")))?;

        // Reject duplicates up-front so callers see a clear error instead of a
        // generic unique-constraint failure.
        if encryption_network::Entity::find_by_id(network_id.to_string())
            .one(&self.db)
            .await?
            .is_some()
        {
            return Err(EncryptionServiceError::NetworkAlreadyExists);
        }

        let now = now_rfc3339();
        let ceremony_id = format!("ceremony:{}:{now}", network_id);

        encryption_ceremony::ActiveModel {
            ceremony_id: Set(ceremony_id.clone()),
            network_id: Set(network_id.to_string()),
            kind: Set("initial".to_string()),
            state: Set("started".to_string()),
            transcript_hash: Set(None),
            started_at: Set(now.clone()),
            completed_at: Set(None),
            failure: Set(None),
        }
        .insert(&self.db)
        .await?;

        let generated = self.backend.generate()?;
        let transcript = hash_hex(&generated.public_key);

        let model = encryption_network::ActiveModel {
            network_id: Set(network_id.to_string()),
            principal: Set(req.principal.clone()),
            name: Set(req.name.clone()),
            alg: Set(generated.alg.clone()),
            key_version: Set(1),
            public_key: Set(generated.public_key.clone()),
            state: Set(NetworkState::Active.as_str().to_string()),
            threshold_n: Set(req.threshold.n),
            threshold_t: Set(req.threshold.t),
            key_backend: Set(self.backend.kind().as_str().to_string()),
            sealed_private_key: Set(Some(generated.sealed_private_key)),
            created_at: Set(now.clone()),
            updated_at: Set(now.clone()),
        };
        model.insert(&self.db).await?;

        encryption_network_member::ActiveModel {
            network_id: Set(network_id.to_string()),
            node_id: Set(self.node_did.clone()),
            role: Set("primary".to_string()),
            share_index: Set(0),
            joined_at: Set(now.clone()),
        }
        .insert(&self.db)
        .await?;

        let mut ceremony_active: encryption_ceremony::ActiveModel =
            encryption_ceremony::Entity::find_by_id(ceremony_id.clone())
                .one(&self.db)
                .await?
                .ok_or(EncryptionServiceError::NetworkNotFound)?
                .into();
        ceremony_active.state = Set("completed".to_string());
        ceremony_active.transcript_hash = Set(Some(transcript));
        ceremony_active.completed_at = Set(Some(now.clone()));
        ceremony_active.update(&self.db).await?;

        Ok(NetworkDescriptor {
            network_id,
            principal: req.principal,
            name: req.name,
            members: vec![NetworkMemberDescriptor {
                node_id: self.node_did.clone(),
                role: "primary".to_string(),
            }],
            threshold: req.threshold,
            state: NetworkState::Active,
            public_encryption_key: generated.public_key,
            alg: generated.alg,
            key_version: 1,
            key_backend: self.backend.kind(),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub async fn get_network(
        &self,
        network_id: &NetworkId,
    ) -> Result<NetworkDescriptor, EncryptionServiceError> {
        let model = encryption_network::Entity::find_by_id(network_id.to_string())
            .one(&self.db)
            .await?
            .ok_or(EncryptionServiceError::NetworkNotFound)?;

        let members = encryption_network_member::Entity::find()
            .filter(encryption_network_member::Column::NetworkId.eq(network_id.to_string()))
            .all(&self.db)
            .await?
            .into_iter()
            .map(|m| NetworkMemberDescriptor {
                node_id: m.node_id,
                role: m.role,
            })
            .collect();

        let state = NetworkState::parse(&model.state).ok_or_else(|| {
            EncryptionServiceError::InvalidBody(format!("unknown network state: {}", model.state))
        })?;
        let backend =
            KeyBackendKind::parse(&model.key_backend).unwrap_or(KeyBackendKind::LocalOneOfOne);

        Ok(NetworkDescriptor {
            network_id: network_id.clone(),
            principal: model.principal,
            name: model.name,
            members,
            threshold: Threshold {
                n: model.threshold_n,
                t: model.threshold_t,
            },
            state,
            public_encryption_key: model.public_key,
            alg: model.alg,
            key_version: model.key_version,
            key_backend: backend,
            created_at: model.created_at,
            updated_at: model.updated_at,
        })
    }

    pub async fn get_network_by_name(
        &self,
        name: &str,
        principal: Option<&str>,
    ) -> Result<NetworkDescriptor, EncryptionServiceError> {
        if let Some(principal) = principal {
            let network_id =
                NetworkId::new(principal.to_string(), name.to_string()).map_err(|e| {
                    EncryptionServiceError::InvalidBody(format!("invalid network id: {e}"))
                })?;
            return self.get_network(&network_id).await;
        }

        let model = encryption_network::Entity::find()
            .filter(encryption_network::Column::Name.eq(name))
            .filter(encryption_network::Column::State.eq(NetworkState::Active.as_str()))
            .one(&self.db)
            .await?
            .ok_or(EncryptionServiceError::NetworkNotFound)?;
        let network_id: NetworkId = model.network_id.parse().map_err(|e| {
            EncryptionServiceError::InvalidBody(format!("invalid stored network id: {e}"))
        })?;
        self.get_network(&network_id).await
    }

    pub async fn revoke_network(
        &self,
        network_id: &NetworkId,
    ) -> Result<(), EncryptionServiceError> {
        let existing = encryption_network::Entity::find_by_id(network_id.to_string())
            .one(&self.db)
            .await?
            .ok_or(EncryptionServiceError::NetworkNotFound)?;

        let mut active: encryption_network::ActiveModel = existing.into();
        active.state = Set(NetworkState::Revoked.as_str().to_string());
        active.updated_at = Set(now_rfc3339());
        active.update(&self.db).await?;
        Ok(())
    }

    pub async fn verify_network_admin_invocation(
        &self,
        network_id: &NetworkId,
        action: &str,
        invocation: &NetworkAdminInvocation,
        body_value: &Value,
    ) -> Result<(), EncryptionServiceError> {
        if invocation.facts.ty != NETWORK_ADMIN_TYPE {
            return Err(EncryptionServiceError::WrongInvocationType);
        }
        if invocation.audience != self.node_did {
            return Err(EncryptionServiceError::AudienceMismatch);
        }
        if invocation.facts.target_node != self.node_did {
            return Err(EncryptionServiceError::TargetNodeMismatch);
        }
        if &invocation.facts.network_id != network_id {
            return Err(EncryptionServiceError::NetworkMismatch);
        }
        if invocation.facts.action != action {
            return Err(EncryptionServiceError::Unauthorized);
        }
        let cap = invocation
            .att
            .iter()
            .find(|c| c.can == action)
            .ok_or(EncryptionServiceError::Unauthorized)?;
        if cap.with != network_id.to_string() {
            return Err(EncryptionServiceError::NetworkMismatch);
        }
        if invocation.issuer != network_id.principal() {
            return Err(EncryptionServiceError::PrincipalMismatch);
        }
        let expected_body_hash = canonical_hash(body_value);
        if expected_body_hash != invocation.facts.body_hash {
            return Err(EncryptionServiceError::HashMismatch("bodyHash"));
        }

        self.validate_invocation_time(invocation.not_before, invocation.exp)?;
        self.verify_signature(
            &invocation.issuer,
            &invocation.sig,
            &invocation.unsigned_payload(),
        )?;
        self.consume_nonce(&invocation.issuer, &invocation.nonce, invocation.exp)
            .await?;
        Ok(())
    }

    pub async fn verify_network_admin_authorized(
        &self,
        network_id: &NetworkId,
        action: &str,
        invocation: &InvocationInfo,
        body_value: &Value,
    ) -> Result<(), EncryptionServiceError> {
        let facts = native_network_admin_facts(invocation)?;
        if facts.ty != NETWORK_ADMIN_TYPE {
            return Err(EncryptionServiceError::WrongInvocationType);
        }
        if invocation.invocation.payload().audience.to_string() != self.node_did {
            return Err(EncryptionServiceError::AudienceMismatch);
        }
        if facts.target_node != self.node_did {
            return Err(EncryptionServiceError::TargetNodeMismatch);
        }
        if &facts.network_id != network_id {
            return Err(EncryptionServiceError::NetworkMismatch);
        }
        if facts.action != action {
            return Err(EncryptionServiceError::Unauthorized);
        }
        let cap = invocation
            .capabilities
            .iter()
            .find(|c| c.ability.to_string() == action)
            .ok_or(EncryptionServiceError::Unauthorized)?;
        if cap.resource.to_string() != network_id.to_string() {
            return Err(EncryptionServiceError::NetworkMismatch);
        }
        let expected_body_hash = canonical_hash(body_value);
        if expected_body_hash != facts.body_hash {
            return Err(EncryptionServiceError::HashMismatch("bodyHash"));
        }

        let exp = native_invocation_exp(invocation)?;
        self.consume_nonce(
            &invocation.invoker,
            native_invocation_nonce(invocation)?,
            exp,
        )
        .await?;
        Ok(())
    }

    /// Verify a decrypt invocation + body and produce a signed response with
    /// the symmetric key rewrapped to the receiver public key.
    ///
    /// `body_value` is the raw JSON the client posted. We canonicalize it
    /// ourselves so the body-hash binding does not depend on client-side
    /// formatting.
    pub async fn decrypt(
        &self,
        network_id: &NetworkId,
        invocation: &DecryptInvocation,
        body_value: &Value,
    ) -> Result<VerifiedDecrypt, EncryptionServiceError> {
        let body: DecryptRequestBody = serde_json::from_value(body_value.clone())
            .map_err(|e| EncryptionServiceError::InvalidBody(e.to_string()))?;

        // ---- Static invariants ----
        if body.ty != DECRYPT_REQUEST_TYPE || invocation.facts.ty != DECRYPT_REQUEST_TYPE {
            return Err(EncryptionServiceError::WrongInvocationType);
        }
        if invocation.audience != self.node_did {
            self.record_audit(invocation, network_id, "denied:audience")
                .await?;
            return Err(EncryptionServiceError::AudienceMismatch);
        }
        if invocation.facts.target_node != self.node_did || body.target_node != self.node_did {
            self.record_audit(invocation, network_id, "denied:target-node")
                .await?;
            return Err(EncryptionServiceError::TargetNodeMismatch);
        }
        if &invocation.facts.network_id != network_id || &body.network_id != network_id {
            return Err(EncryptionServiceError::NetworkMismatch);
        }
        self.verify_invocation_signature(invocation)?;

        // Capability binding.
        let cap = invocation
            .att
            .iter()
            .find(|c| c.can == DECRYPT_ACTION)
            .ok_or(EncryptionServiceError::Unauthorized)?;
        if cap.with != network_id.to_string() {
            return Err(EncryptionServiceError::NetworkMismatch);
        }
        if invocation.issuer != network_id.principal() {
            return Err(EncryptionServiceError::PrincipalMismatch);
        }

        // ---- Network state ----
        let descriptor = self.get_network(network_id).await?;
        match descriptor.state {
            NetworkState::Active => {}
            NetworkState::Revoked => {
                self.record_audit(invocation, network_id, "denied:revoked")
                    .await?;
                return Err(EncryptionServiceError::NetworkRevoked);
            }
            other => {
                self.record_audit(invocation, network_id, "denied:state")
                    .await?;
                return Err(EncryptionServiceError::NetworkNotActive(
                    other.as_str().to_string(),
                ));
            }
        }
        if descriptor.alg != body.alg || descriptor.key_version != body.key_version {
            return Err(EncryptionServiceError::AlgKeyVersionMismatch);
        }
        if descriptor.alg != invocation.facts.alg
            || descriptor.key_version != invocation.facts.key_version
        {
            return Err(EncryptionServiceError::AlgKeyVersionMismatch);
        }

        // ---- Time bounds ----
        self.validate_invocation_time(invocation.not_before, invocation.exp)?;

        // ---- Hash bindings ----
        let receiver_key_bytes =
            decode_base64(&body.receiver_public_key).map_err(EncryptionServiceError::Base64)?;
        let wrapped_key_bytes =
            decode_base64(&body.encrypted_symmetric_key).map_err(EncryptionServiceError::Base64)?;

        let expected_receiver_hash =
            canonical_hash(&Value::String(body.receiver_public_key.clone()));
        if expected_receiver_hash != body.receiver_public_key_hash
            || expected_receiver_hash != invocation.facts.receiver_public_key_hash
        {
            self.record_audit(invocation, network_id, "denied:receiver-hash")
                .await?;
            return Err(EncryptionServiceError::HashMismatch(
                "receiverPublicKeyHash",
            ));
        }

        let expected_key_hash =
            canonical_hash(&Value::String(body.encrypted_symmetric_key.clone()));
        if expected_key_hash != body.encrypted_symmetric_key_hash
            || expected_key_hash != invocation.facts.encrypted_symmetric_key_hash
        {
            self.record_audit(invocation, network_id, "denied:key-hash")
                .await?;
            return Err(EncryptionServiceError::HashMismatch(
                "encryptedSymmetricKeyHash",
            ));
        }

        let expected_body_hash = canonical_hash(body_value);
        if expected_body_hash != invocation.facts.body_hash {
            self.record_audit(invocation, network_id, "denied:body-hash")
                .await?;
            return Err(EncryptionServiceError::HashMismatch("bodyHash"));
        }

        // ---- Replay protection ----
        let invocation_cid = invocation.cid();
        let request_hash =
            hash_hex(&[invocation_cid.as_bytes(), expected_body_hash.as_bytes()].concat());
        if let Err(err) = self
            .consume_nonce(&invocation.issuer, &invocation.nonce, invocation.exp)
            .await
        {
            if matches!(err, EncryptionServiceError::NonceReplay) {
                self.record_audit(invocation, network_id, "denied:replay")
                    .await?;
            }
            return Err(err);
        }

        // ---- Unwrap + rewrap ----
        let sealed = descriptor.key_backend; // unused but documents the choice
        let _ = sealed;
        let network_row = encryption_network::Entity::find_by_id(network_id.to_string())
            .one(&self.db)
            .await?
            .ok_or(EncryptionServiceError::NetworkNotFound)?;
        let sealed_private_key =
            network_row
                .sealed_private_key
                .as_deref()
                .ok_or(EncryptionServiceError::Backend(
                    KeyBackendError::SealedKeyMissing,
                ))?;
        let symmetric = self
            .backend
            .unwrap(sealed_private_key, &wrapped_key_bytes)?;
        let rewrapped = self.backend.rewrap(&symmetric, &receiver_key_bytes)?;
        // Best-effort: zeroize the transient symmetric key copy.
        drop(symmetric);

        let mut response = DecryptResponseBody {
            ty: DECRYPT_RESULT_TYPE.to_string(),
            target_node: self.node_did.clone(),
            network_id: network_id.clone(),
            invocation_cid: invocation_cid.clone(),
            encrypted_symmetric_key_hash: expected_key_hash,
            receiver_public_key_hash: expected_receiver_hash,
            wrapped_key: encode_base64(&rewrapped),
            alg: descriptor.alg.clone(),
            key_version: descriptor.key_version,
            request_hash: request_hash.clone(),
            node_id: self.node_did.clone(),
            node_signature: String::new(),
        };
        response.node_signature = self.sign_response(&response)?;

        self.record_audit(invocation, network_id, "allowed").await?;

        Ok(VerifiedDecrypt {
            response,
            request_hash,
        })
    }

    /// Decrypt path for native TinyCloud UCAN invocations produced by
    /// node-sdk's `invokeAny`. Signature/proof-chain validation is performed
    /// by the node auth DAG before this method is called.
    pub async fn decrypt_authorized(
        &self,
        network_id: &NetworkId,
        invocation: &InvocationInfo,
        body_value: &Value,
    ) -> Result<VerifiedDecrypt, EncryptionServiceError> {
        let body: DecryptRequestBody = serde_json::from_value(body_value.clone())
            .map_err(|e| EncryptionServiceError::InvalidBody(e.to_string()))?;
        let facts = native_decrypt_facts(invocation)?;

        if body.ty != DECRYPT_REQUEST_TYPE || facts.ty != DECRYPT_REQUEST_TYPE {
            return Err(EncryptionServiceError::WrongInvocationType);
        }
        if invocation.invocation.payload().audience.to_string() != self.node_did {
            self.record_native_audit(invocation, network_id, &facts, "denied:audience")
                .await?;
            return Err(EncryptionServiceError::AudienceMismatch);
        }
        if facts.target_node != self.node_did || body.target_node != self.node_did {
            self.record_native_audit(invocation, network_id, &facts, "denied:target-node")
                .await?;
            return Err(EncryptionServiceError::TargetNodeMismatch);
        }
        if &facts.network_id != network_id || &body.network_id != network_id {
            return Err(EncryptionServiceError::NetworkMismatch);
        }

        let cap = invocation
            .capabilities
            .iter()
            .find(|c| c.ability.to_string() == DECRYPT_ACTION)
            .ok_or(EncryptionServiceError::Unauthorized)?;
        if cap.resource.to_string() != network_id.to_string() {
            return Err(EncryptionServiceError::NetworkMismatch);
        }

        let descriptor = self.get_network(network_id).await?;
        match descriptor.state {
            NetworkState::Active => {}
            NetworkState::Revoked => {
                self.record_native_audit(invocation, network_id, &facts, "denied:revoked")
                    .await?;
                return Err(EncryptionServiceError::NetworkRevoked);
            }
            other => {
                self.record_native_audit(invocation, network_id, &facts, "denied:state")
                    .await?;
                return Err(EncryptionServiceError::NetworkNotActive(
                    other.as_str().to_string(),
                ));
            }
        }
        if descriptor.alg != body.alg || descriptor.key_version != body.key_version {
            return Err(EncryptionServiceError::AlgKeyVersionMismatch);
        }
        if descriptor.alg != facts.alg || descriptor.key_version != facts.key_version {
            return Err(EncryptionServiceError::AlgKeyVersionMismatch);
        }

        let exp = native_invocation_exp(invocation)?;
        self.validate_invocation_time(native_invocation_not_before(invocation), exp)?;

        let receiver_key_bytes =
            decode_base64(&body.receiver_public_key).map_err(EncryptionServiceError::Base64)?;
        let wrapped_key_bytes =
            decode_base64(&body.encrypted_symmetric_key).map_err(EncryptionServiceError::Base64)?;

        let expected_receiver_hash =
            canonical_hash(&Value::String(body.receiver_public_key.clone()));
        if expected_receiver_hash != body.receiver_public_key_hash
            || expected_receiver_hash != facts.receiver_public_key_hash
        {
            self.record_native_audit(invocation, network_id, &facts, "denied:receiver-hash")
                .await?;
            return Err(EncryptionServiceError::HashMismatch(
                "receiverPublicKeyHash",
            ));
        }

        let expected_key_hash =
            canonical_hash(&Value::String(body.encrypted_symmetric_key.clone()));
        if expected_key_hash != body.encrypted_symmetric_key_hash
            || expected_key_hash != facts.encrypted_symmetric_key_hash
        {
            self.record_native_audit(invocation, network_id, &facts, "denied:key-hash")
                .await?;
            return Err(EncryptionServiceError::HashMismatch(
                "encryptedSymmetricKeyHash",
            ));
        }

        let expected_body_hash = canonical_hash(body_value);
        if expected_body_hash != facts.body_hash {
            self.record_native_audit(invocation, network_id, &facts, "denied:body-hash")
                .await?;
            return Err(EncryptionServiceError::HashMismatch("bodyHash"));
        }

        let invocation_cid = native_invocation_cid(invocation)?;
        let request_hash =
            hash_hex(&[invocation_cid.as_bytes(), expected_body_hash.as_bytes()].concat());
        if let Err(err) = self
            .consume_nonce(
                &invocation.invoker,
                native_invocation_nonce(invocation)?,
                exp,
            )
            .await
        {
            if matches!(err, EncryptionServiceError::NonceReplay) {
                self.record_native_audit(invocation, network_id, &facts, "denied:replay")
                    .await?;
            }
            return Err(err);
        }

        let network_row = encryption_network::Entity::find_by_id(network_id.to_string())
            .one(&self.db)
            .await?
            .ok_or(EncryptionServiceError::NetworkNotFound)?;
        let sealed_private_key =
            network_row
                .sealed_private_key
                .as_deref()
                .ok_or(EncryptionServiceError::Backend(
                    KeyBackendError::SealedKeyMissing,
                ))?;
        let symmetric = self
            .backend
            .unwrap(sealed_private_key, &wrapped_key_bytes)?;
        let rewrapped = self.backend.rewrap(&symmetric, &receiver_key_bytes)?;
        drop(symmetric);

        let mut response = DecryptResponseBody {
            ty: DECRYPT_RESULT_TYPE.to_string(),
            target_node: self.node_did.clone(),
            network_id: network_id.clone(),
            invocation_cid: invocation_cid.clone(),
            encrypted_symmetric_key_hash: expected_key_hash,
            receiver_public_key_hash: expected_receiver_hash,
            wrapped_key: encode_base64(&rewrapped),
            alg: descriptor.alg.clone(),
            key_version: descriptor.key_version,
            request_hash: request_hash.clone(),
            node_id: self.node_did.clone(),
            node_signature: String::new(),
        };
        response.node_signature = self.sign_response(&response)?;

        self.record_native_audit(invocation, network_id, &facts, "allowed")
            .await?;

        Ok(VerifiedDecrypt {
            response,
            request_hash,
        })
    }

    fn sign_response(
        &self,
        response: &DecryptResponseBody,
    ) -> Result<String, EncryptionServiceError> {
        let mut value = serde_json::to_value(response)
            .map_err(|err| EncryptionServiceError::Signing(err.to_string()))?;
        if let Value::Object(map) = &mut value {
            map.remove("nodeSignature");
        }
        let message = canonical_json_bytes(&value);
        if let Some(keypair) = &self.node_keypair {
            let signature = keypair
                .sign(&message)
                .map_err(|err| EncryptionServiceError::Signing(err.to_string()))?;
            return Ok(encode_base64(&signature));
        }

        // Unit tests can construct the service with only a node DID. Keep the
        // wire format as base64 bytes even for that unsigned test mode.
        Ok(encode_base64(&hash_hex(&message).into_bytes()))
    }

    fn verify_invocation_signature(
        &self,
        invocation: &DecryptInvocation,
    ) -> Result<(), EncryptionServiceError> {
        self.verify_signature(
            &invocation.issuer,
            &invocation.sig,
            &invocation.unsigned_payload(),
        )
    }

    fn verify_signature(
        &self,
        issuer: &str,
        sig: &str,
        payload: &Value,
    ) -> Result<(), EncryptionServiceError> {
        let public_key =
            did_key_public_key(issuer).map_err(EncryptionServiceError::SignatureInvalid)?;
        let sig = decode_base64(sig)
            .map_err(|err| EncryptionServiceError::SignatureInvalid(err.to_string()))?;
        let message = canonical_json_bytes(payload);
        if public_key.verify(&message, &sig) {
            return Ok(());
        }
        Err(EncryptionServiceError::SignatureInvalid(
            "signature does not verify for issuer did:key".to_string(),
        ))
    }

    fn validate_invocation_time(
        &self,
        not_before: Option<i64>,
        exp: i64,
    ) -> Result<(), EncryptionServiceError> {
        let now_ts = OffsetDateTime::now_utc().unix_timestamp();
        if let Some(nbf) = not_before {
            if now_ts < nbf {
                return Err(EncryptionServiceError::NotYetValid);
            }
        }
        if exp <= now_ts {
            return Err(EncryptionServiceError::Expired);
        }
        if exp - now_ts > self.invocation_ttl_seconds {
            return Err(EncryptionServiceError::Expired);
        }
        Ok(())
    }

    async fn consume_nonce(
        &self,
        requester_did: &str,
        nonce: &str,
        exp: i64,
    ) -> Result<(), EncryptionServiceError> {
        let nonce_expires_at = OffsetDateTime::from_unix_timestamp(exp)
            .unwrap_or_else(|_| OffsetDateTime::now_utc())
            .format(&Rfc3339)
            .unwrap_or_else(|_| now_rfc3339());
        let insert = encryption_nonce::ActiveModel {
            requester_did: Set(requester_did.to_string()),
            nonce: Set(nonce.to_string()),
            expires_at: Set(nonce_expires_at),
        };
        if let Err(err) = insert.insert(&self.db).await {
            if is_unique_violation(&err) {
                return Err(EncryptionServiceError::NonceReplay);
            }
            return Err(err.into());
        }
        Ok(())
    }

    async fn record_audit(
        &self,
        invocation: &DecryptInvocation,
        network_id: &NetworkId,
        outcome: &str,
    ) -> Result<(), EncryptionServiceError> {
        let cid = invocation.cid();
        let request_hash =
            hash_hex(&[cid.as_bytes(), invocation.facts.body_hash.as_bytes()].concat());
        // Upsert-style: if the same request hash + outcome arrives twice (e.g.
        // replay attempt) we keep the first decision. Ignore unique conflicts.
        let row = encryption_audit::ActiveModel {
            request_hash: Set(request_hash),
            requester: Set(invocation.issuer.clone()),
            network_id: Set(network_id.to_string()),
            node_id: Set(self.node_did.clone()),
            outcome: Set(outcome.to_string()),
            decided_at: Set(now_rfc3339()),
        };
        if let Err(err) = row.insert(&self.db).await {
            if !is_unique_violation(&err) {
                return Err(err.into());
            }
        }
        Ok(())
    }

    async fn record_native_audit(
        &self,
        invocation: &InvocationInfo,
        network_id: &NetworkId,
        facts: &DecryptFacts,
        outcome: &str,
    ) -> Result<(), EncryptionServiceError> {
        let cid = native_invocation_cid(invocation)?;
        let request_hash = hash_hex(&[cid.as_bytes(), facts.body_hash.as_bytes()].concat());
        let row = encryption_audit::ActiveModel {
            request_hash: Set(request_hash),
            requester: Set(invocation.invoker.clone()),
            network_id: Set(network_id.to_string()),
            node_id: Set(self.node_did.clone()),
            outcome: Set(outcome.to_string()),
            decided_at: Set(now_rfc3339()),
        };
        if let Err(err) = row.insert(&self.db).await {
            if !is_unique_violation(&err) {
                return Err(err.into());
            }
        }
        Ok(())
    }
}

fn native_decrypt_facts(
    invocation: &InvocationInfo,
) -> Result<DecryptFacts, EncryptionServiceError> {
    native_fact(invocation)
}

fn native_network_admin_facts(
    invocation: &InvocationInfo,
) -> Result<NetworkAdminFacts, EncryptionServiceError> {
    native_fact(invocation)
}

fn native_fact<T>(invocation: &InvocationInfo) -> Result<T, EncryptionServiceError>
where
    T: for<'de> Deserialize<'de>,
{
    invocation
        .invocation
        .payload()
        .facts
        .as_ref()
        .and_then(|facts| {
            facts
                .iter()
                .find_map(|fact| serde_json::from_value::<T>(fact.clone()).ok())
        })
        .ok_or_else(|| {
            EncryptionServiceError::InvalidBody("missing encryption invocation facts".to_string())
        })
}

fn native_invocation_exp(invocation: &InvocationInfo) -> Result<i64, EncryptionServiceError> {
    Ok(invocation.invocation.payload().expiration.as_seconds() as i64)
}

fn native_invocation_not_before(invocation: &InvocationInfo) -> Option<i64> {
    invocation
        .invocation
        .payload()
        .not_before
        .map(|time| time.as_seconds() as i64)
}

fn native_invocation_nonce(invocation: &InvocationInfo) -> Result<&str, EncryptionServiceError> {
    invocation
        .invocation
        .payload()
        .nonce
        .as_deref()
        .ok_or_else(|| EncryptionServiceError::InvalidBody("missing nonce".to_string()))
}

fn native_invocation_cid(invocation: &InvocationInfo) -> Result<String, EncryptionServiceError> {
    let encoded = invocation
        .invocation
        .encode()
        .map_err(|err| EncryptionServiceError::InvalidBody(err.to_string()))?;
    Ok(hash(encoded.as_bytes()).to_cid(0x55).to_string())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WellKnownRecord {
    pub network_id: String,
    pub principal: String,
    pub name: String,
    pub alg: String,
    pub key_version: i64,
    #[serde(rename = "publicEncryptionKey")]
    pub public_encryption_key: String,
    pub state: String,
    pub key_backend: String,
}

impl From<&NetworkDescriptor> for WellKnownRecord {
    fn from(d: &NetworkDescriptor) -> Self {
        Self {
            network_id: d.network_id.to_string(),
            principal: d.principal.clone(),
            name: d.name.clone(),
            alg: d.alg.clone(),
            key_version: d.key_version,
            public_encryption_key: encode_base64(&d.public_encryption_key),
            state: d.state.as_str().to_string(),
            key_backend: d.key_backend.as_str().to_string(),
        }
    }
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn is_unique_violation(err: &DbErr) -> bool {
    let s = err.to_string().to_lowercase();
    s.contains("unique") || s.contains("primary") || s.contains("duplicate")
}

fn encode_base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn decode_base64(s: &str) -> Result<Vec<u8>, &'static str> {
    STANDARD.decode(s).map_err(|_| "invalid base64")
}

fn did_key_public_key(did: &str) -> Result<PublicKey, String> {
    let encoded = did
        .strip_prefix("did:key:")
        .ok_or_else(|| "issuer must be a did:key".to_string())?;
    let (_base, bytes) = tinycloud_auth::ipld_core::cid::multibase::decode(encoded)
        .map_err(|err| err.to_string())?;
    let key_bytes = match bytes.as_slice() {
        [0xed, rest @ ..] if rest.len() == 32 => rest,
        [0xed, 0x01, rest @ ..] if rest.len() == 32 => rest,
        _ => return Err("issuer did:key is not an ed25519 public key".to_string()),
    };
    let ed = libp2p::identity::ed25519::PublicKey::try_from_bytes(key_bytes)
        .map_err(|err| err.to_string())?;
    Ok(ed.into())
}
