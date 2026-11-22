//! TC-3810: wallet-signed CACAO delegation mode (`xyz.tinycloud.policy/delegationMode`).
//!
//! Covers registration, invocation (direct vs descendant), multi-parent,
//! root-authority, revocation, tampered signatures, pre-lock enforcement (single,
//! batch with in-memory parents, core read/write/public invocations), and
//! boot-time reindexing (plaintext, encrypted, malformed stored rows, and
//! interrupted-restart recovery).
use super::*;
use crate::storage::memory::{MemoryStaging, MemoryStore};
use crate::types::Metadata;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures::AsyncWriteExt;
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;
use tinycloud_auth::{
    authorization::{HeaderEncode, TinyCloudDelegation, TinyCloudInvocation, TinyCloudRevocation},
    cacaos::{
        siwe::{encode_eip55, Message, Version},
        siwe_cacao::{Eip191, Payload as CacaoPayload, Signature, SiweCacao},
    },
    ipld_core::cid::Cid,
    resolver::DID_METHODS,
    siwe_recap::{Capability as RecapCapability, DelegationModeFact, RESOURCE_PREFIX},
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload as UcanPayload,
    },
    ucan_capabilities_object::Capabilities,
};

struct Wallet {
    key: SigningKey,
    address: [u8; 20],
    did: String,
}

impl Wallet {
    fn from_seed(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let public = key.verifying_key().to_encoded_point(false);
        let address: [u8; 20] = Keccak256::digest(&public.as_bytes()[1..])[12..]
            .try_into()
            .unwrap();
        let did = format!("did:pkh:eip155:1:0x{}", encode_eip55(&address));
        Self { key, address, did }
    }

    fn sign_message(&self, message: &Message) -> SiweCacao {
        let (sig, recovery) = self
            .key
            .sign_prehash_recoverable(&message.eip191_hash().unwrap())
            .unwrap();
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&sig.to_bytes());
        bytes[64] = u8::from(recovery) + 27;
        CacaoPayload::from(message.clone()).sign::<Eip191>(Signature::from(bytes))
    }
}

fn verification_method(key: &JWK) -> (String, String) {
    let did = DID_METHODS.generate(key, "key").unwrap().to_string();
    let vm = format!("{did}#{}", did.rsplit(':').next().unwrap());
    (did, vm)
}

fn base_siwe_message(wallet: &Wallet, audience: &str, nonce: &str, is_child: bool) -> Message {
    let now = OffsetDateTime::now_utc();
    let (nbf_offset, exp_offset) = if is_child {
        (time::Duration::seconds(30), time::Duration::minutes(45))
    } else {
        (time::Duration::minutes(2), time::Duration::hours(2))
    };
    Message {
        scheme: Some("https".parse().unwrap()),
        domain: "openkey.tinycloud.invalid".parse().unwrap(),
        address: wallet.address,
        statement: None,
        uri: audience.parse().unwrap(),
        version: Version::V1,
        chain_id: 1,
        nonce: nonce.to_string(),
        issued_at: now.into(),
        expiration_time: Some((now + exp_offset).into()),
        not_before: Some((now - nbf_offset).into()),
        request_id: None,
        resources: vec![],
    }
}

fn signed_cacao_token(
    wallet: &Wallet,
    audience: &str,
    grants: &[(&str, &str)],
    parents: &[Cid],
    mode: Option<DelegationModeFact>,
    nonce: &str,
) -> (String, Cid, SiweCacao) {
    let mut recap = RecapCapability::<serde_json::Value>::new();
    for (resource, ability) in grants {
        recap.with_action(
            resource.parse().unwrap(),
            ability.parse().unwrap(),
            [BTreeMap::new()],
        );
    }
    let recap = recap.with_proofs(parents);
    let recap = match mode {
        Some(m) => recap.with_delegation_mode(m),
        None => recap,
    };
    let message = recap
        .build_message(base_siwe_message(
            wallet,
            audience,
            nonce,
            !parents.is_empty(),
        ))
        .unwrap();
    let cacao = wallet.sign_message(&message);
    let token = TinyCloudDelegation::Cacao(Box::new(cacao.clone()))
        .encode()
        .unwrap();
    let (_, canonical) = TinyCloudDelegation::decode(&token).unwrap();
    let cid = crate::hash::hash(&canonical).to_cid(0x55);
    (token, cid, cacao)
}

/// Build a real wallet-signed CACAO whose ReCap carries a custom raw top-level
/// field fragment (e.g. a malformed or duplicate `delegationMode`) so we can
/// simulate pre-upgrade stored rows created under an old node.
fn signed_cacao_with_raw_recap_tail(
    wallet: &Wallet,
    audience: &str,
    grants: &[(&str, &str)],
    raw_tail: &str,
    nonce: &str,
) -> (Vec<u8>, Hash, Cid) {
    let mut recap = RecapCapability::<serde_json::Value>::new();
    for (resource, ability) in grants {
        recap.with_action(
            resource.parse().unwrap(),
            ability.parse().unwrap(),
            [BTreeMap::new()],
        );
    }
    let statement = recap.to_statement();
    let att_json = serde_json::to_string(recap.abilities()).unwrap();
    let raw_recap = format!(r#"{{"att":{att_json},"prf":[],{raw_tail}}}"#);
    let encoded = URL_SAFE_NO_PAD.encode(raw_recap.as_bytes());
    let mut message = base_siwe_message(wallet, audience, nonce, false);
    message.statement = Some(statement);
    message
        .resources
        .push(format!("{RESOURCE_PREFIX}{encoded}").parse().unwrap());
    let cacao = wallet.sign_message(&message);
    let canonical = serde_ipld_dagcbor::to_vec(&cacao).unwrap();
    let hash = crate::hash::hash(&canonical);
    (canonical, hash, hash.to_cid(0x55))
}

fn signed_ucan_delegation(
    issuer: &JWK,
    audience: &str,
    grants: &[(&str, &str)],
    parents: &[Cid],
    terminal: bool,
) -> (Delegation, Cid) {
    let mut caps = Capabilities::<serde_json::Value>::new();
    for (resource, ability) in grants {
        caps.with_action(
            resource.parse().unwrap(),
            ability.parse().unwrap(),
            [BTreeMap::new()],
        );
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let facts = terminal.then(|| {
        vec![serde_json::json!({
            crate::util::DelegationMode::FACT_KEY: "terminal"
        })]
    });
    let token = UcanPayload::<serde_json::Value> {
        issuer: verification_method(issuer).1.parse().unwrap(),
        audience: audience.parse().unwrap(),
        not_before: Some(NumericDate::try_from_seconds((now - 15) as f64).unwrap()),
        expiration: NumericDate::try_from_seconds((now + 1200) as f64).unwrap(),
        nonce: Some(format!("tc3810-del-{}", rand::random::<u64>())),
        facts,
        proof: parents.to_vec(),
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, issuer)
    .unwrap()
    .encode()
    .unwrap();
    let delegation = Delegation::from_header_ser::<TinyCloudDelegation>(&token).unwrap();
    let cid = delegation.content_hash().to_cid(0x55);
    (delegation, cid)
}

fn signed_invocation(issuer: &JWK, grants: &[(&str, &str)], parents: &[Cid]) -> Invocation {
    let mut caps = Capabilities::<serde_json::Value>::new();
    for (resource, ability) in grants {
        caps.with_action(
            resource.parse().unwrap(),
            ability.parse().unwrap(),
            [BTreeMap::new()],
        );
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let (did, vm) = verification_method(issuer);
    let token = UcanPayload::<serde_json::Value> {
        issuer: vm.parse().unwrap(),
        audience: did.parse().unwrap(),
        not_before: Some(NumericDate::try_from_seconds((now - 60) as f64).unwrap()),
        expiration: NumericDate::try_from_seconds((now + 60) as f64).unwrap(),
        nonce: Some(format!("tc3810-inv-{}", rand::random::<u64>())),
        facts: None,
        proof: parents.to_vec(),
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, issuer)
    .unwrap()
    .encode()
    .unwrap();
    Invocation::from_header_ser::<TinyCloudInvocation>(&token).unwrap()
}

fn signed_cacao_revocation(wallet: &Wallet, target: Cid, nonce: &str) -> Revocation {
    let mut message = base_siwe_message(wallet, &format!("ucan:{target}"), nonce, false);
    message.statement = Some("Revoke delegation".to_string());
    let cacao = wallet.sign_message(&message);
    let token = TinyCloudRevocation::Cacao(Box::new(cacao))
        .encode()
        .unwrap();
    Revocation::from_header_ser::<TinyCloudRevocation>(&token).unwrap()
}

fn parse_delegation(token: &str) -> Delegation {
    Delegation::from_header_ser::<TinyCloudDelegation>(token).unwrap()
}

fn must_ok<T, E: std::fmt::Display>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("unexpected error: {error}"))
}

fn must_err<T, E>(result: Result<T, E>) -> E {
    match result {
        Err(error) => error,
        Ok(_) => panic!("expected error, got Ok"),
    }
}

struct Fixture {
    db: SpaceDatabase<sea_orm::DatabaseConnection, MemoryStore, StaticSecret>,
    url: String,
    wallet: Wallet,
    space: SpaceId,
    kv_res: String,
    kv_path: Path,
    secret_res: String,
    _dir: tempfile::TempDir,
}

impl Fixture {
    async fn new(encryption: Option<ColumnEncryption>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            dir.path().join("tc3810.sqlite").display()
        );
        let conn = sea_orm::Database::connect(&url).await.unwrap();
        let mut db = SpaceDatabase::new_with_encryption(
            conn,
            MemoryStore::default(),
            StaticSecret::new(vec![0x55; 32]).unwrap(),
            encryption,
        )
        .await
        .unwrap();
        db.named_keys = true;
        let wallet = Wallet::from_seed(0x11);
        let space: SpaceId = format!(
            "tinycloud:{}:default",
            wallet.did.strip_prefix("did:").unwrap()
        )
        .parse()
        .unwrap();
        space::ActiveModel {
            id: Set(SpaceIdWrap(space.clone())),
        }
        .insert(&db.conn)
        .await
        .unwrap();
        let kv_path: Path = "secrets/api_key".parse().unwrap();
        let kv_res = space
            .clone()
            .to_resource("kv".parse().unwrap(), Some(kv_path.clone()), None, None)
            .to_string();
        let secret_res = format!(
            "urn:tinycloud:encryption:{}:default/secrets/api_key",
            wallet.did
        );
        Self {
            db,
            url,
            wallet,
            space,
            kv_res,
            kv_path,
            secret_res,
            _dir: dir,
        }
    }

    async fn seed_kv_value(&self, owner_holder: &JWK, value: &[u8]) {
        let (holder_did, _) = verification_method(owner_holder);
        let (token, cid, _) = signed_cacao_token(
            &self.wallet,
            &holder_did,
            &[(&self.kv_res, "tinycloud.kv/put")],
            &[],
            Some(DelegationModeFact::Attenuable),
            "seedkv1234",
        );
        must_ok(self.db.delegate(parse_delegation(&token)).await);
        let inv = signed_invocation(owner_holder, &[(&self.kv_res, "tinycloud.kv/put")], &[cid]);
        let mut stage = HashBuffer::new(Vec::new());
        stage.write_all(value).await.unwrap();
        let mut inputs = HashMap::new();
        inputs.insert(
            (self.space.clone(), self.kv_path.clone()),
            (Metadata(BTreeMap::new()), stage),
        );
        must_ok(self.db.invoke::<MemoryStaging>(inv, inputs).await);
    }

    /// Insert a legacy pre-upgrade row directly into `delegation` (with
    /// `facts = None`, as an old node would have stored it) plus its abilities
    /// and parent edges.
    #[allow(clippy::too_many_arguments)]
    async fn insert_pre_upgrade_row(
        &self,
        id: Hash,
        delegator: &str,
        delegatee: &str,
        plaintext: &[u8],
        grants: &[(&str, &str)],
        parents: &[Hash],
        encryption: Option<&ColumnEncryption>,
    ) {
        for did in [delegator, delegatee] {
            actor::ActiveModel {
                id: Set(did.to_string()),
            }
            .insert(&self.db.conn)
            .await
            .ok();
        }
        let stored = crate::encryption::maybe_encrypt(
            encryption,
            plaintext,
            crate::encryption::RowBinding::new(
                "delegation",
                "serialization",
                &[&Vec::<u8>::from(id)],
            ),
        );
        let now = OffsetDateTime::now_utc();
        delegation::ActiveModel {
            id: Set(id),
            delegator: Set(delegator.to_string()),
            delegatee: Set(delegatee.to_string()),
            expiry: Set(Some(now + time::Duration::hours(1))),
            issued_at: Set(Some(now)),
            not_before: Set(Some(now - time::Duration::minutes(1))),
            facts: Set(None),
            serialization: Set(stored),
            serialization_format: Set(if encryption.is_some() { 2 } else { 0 }),
            first_seen_at: Set(Some(now)),
        }
        .insert(&self.db.conn)
        .await
        .unwrap();
        delegation_cid_alias::ActiveModel {
            id: Set(id),
            canonical: Set(id),
            encrypted: Set(encryption.is_some()),
        }
        .insert(&self.db.conn)
        .await
        .unwrap();
        for (resource, ability) in grants {
            abilities::Entity::insert(abilities::ActiveModel {
                delegation: Set(id),
                resource: Set(resource.parse().unwrap()),
                ability: Set((*ability).to_owned().try_into().unwrap()),
                caveats: Set(Default::default()),
            })
            .exec(&self.db.conn)
            .await
            .unwrap();
        }
        for parent in parents {
            parent_delegations::ActiveModel {
                child: Set(id),
                parent: Set(*parent),
            }
            .insert(&self.db.conn)
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
async fn terminal_cacao_direct_use_ok_and_ucan_or_cacao_children_refused() {
    let f = Fixture::new(None).await;
    let seeder = JWK::generate_ed25519().unwrap();
    f.seed_kv_value(&seeder, b"secret-bytes").await;

    let app_key = JWK::generate_ed25519().unwrap();
    let (app_did, _) = verification_method(&app_key);
    let sub_key = JWK::generate_ed25519().unwrap();
    let (sub_did, _) = verification_method(&sub_key);

    // Register multi-ability terminal CACAO T.
    let (t_token, t_cid, _) = signed_cacao_token(
        &f.wallet,
        &app_did,
        &[
            (&f.kv_res, "tinycloud.kv/get"),
            (&f.secret_res, "tinycloud.encryption/decrypt"),
        ],
        &[],
        Some(DelegationModeFact::Terminal),
        "termcacao01",
    );
    must_ok(f.db.delegate(parse_delegation(&t_token)).await);

    // Persisted facts carries terminal mode.
    let row = delegation::Entity::find_by_id(Hash::from(t_cid))
        .one(&f.db.conn)
        .await
        .unwrap()
        .unwrap();
    assert!(delegation::parent_is_terminal(&row));

    // Direct invocation of T by authenticated audience succeeds for both abilities.
    let inv_kv = signed_invocation(&app_key, &[(&f.kv_res, "tinycloud.kv/get")], &[t_cid]);
    must_ok(f.db.invoke::<MemoryStaging>(inv_kv, HashMap::new()).await);
    let inv_dec = signed_invocation(
        &app_key,
        &[(&f.secret_res, "tinycloud.encryption/decrypt")],
        &[t_cid],
    );
    f.db.authorize_invocation(&inv_dec.0, OffsetDateTime::now_utc())
        .await
        .unwrap();

    // UCAN child of T is refused and not stored.
    let (ucan_child, ucan_child_cid) = signed_ucan_delegation(
        &app_key,
        &sub_did,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[t_cid],
        false,
    );
    let err = must_err(f.db.delegate(ucan_child).await);
    assert!(
        matches!(
            err,
            TxError::InvalidDelegation(delegation::DelegationError::TerminalParentCannotRedelegate)
        ),
        "got {err}"
    );
    assert_eq!(err.to_string(), "terminal-parent-cannot-redelegate");
    assert!(
        delegation::Entity::find_by_id(Hash::from(ucan_child_cid))
            .one(&f.db.conn)
            .await
            .unwrap()
            .is_none(),
        "refused UCAN child must not be stored"
    );

    // CACAO child of T (issued by another wallet as delegatee of a terminal CACAO) is refused.
    let other_wallet = Wallet::from_seed(0x22);
    let (t_wallet_token, t_wallet_cid, _) = signed_cacao_token(
        &f.wallet,
        &other_wallet.did,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        Some(DelegationModeFact::Terminal),
        "termcacao02",
    );
    must_ok(f.db.delegate(parse_delegation(&t_wallet_token)).await);
    let (cacao_child_token, cacao_child_cid, _) = signed_cacao_token(
        &other_wallet,
        &sub_did,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[t_wallet_cid],
        None,
        "cacaochild1",
    );
    let err = must_err(f.db.delegate(parse_delegation(&cacao_child_token)).await);
    assert!(
        matches!(
            err,
            TxError::InvalidDelegation(delegation::DelegationError::TerminalParentCannotRedelegate)
        ),
        "got {err}"
    );
    assert!(
        delegation::Entity::find_by_id(Hash::from(cacao_child_cid))
            .one(&f.db.conn)
            .await
            .unwrap()
            .is_none(),
        "refused CACAO child must not be stored"
    );

    // Attenuable CACAO (both absent and explicit "attenuable") still accepts
    // session-key UCAN children and allows invocation.
    for (idx, mode) in [None, Some(DelegationModeFact::Attenuable)]
        .into_iter()
        .enumerate()
    {
        let sess_key = JWK::generate_ed25519().unwrap();
        let (sess_did, _) = verification_method(&sess_key);
        let (a_token, a_cid, _) = signed_cacao_token(
            &f.wallet,
            &sess_did,
            &[(&f.kv_res, "tinycloud.kv/get")],
            &[],
            mode,
            &format!("attencacao{idx}"),
        );
        must_ok(f.db.delegate(parse_delegation(&a_token)).await);
        let (child, child_cid) = signed_ucan_delegation(
            &sess_key,
            &sub_did,
            &[(&f.kv_res, "tinycloud.kv/get")],
            &[a_cid],
            false,
        );
        must_ok(f.db.delegate(child).await);
        let inv = signed_invocation(&sub_key, &[(&f.kv_res, "tinycloud.kv/get")], &[child_cid]);
        must_ok(f.db.invoke::<MemoryStaging>(inv, HashMap::new()).await);
    }
}

#[tokio::test]
async fn strip_or_change_signed_mode_field_fails_signature_verification() {
    let f = Fixture::new(None).await;
    let app_key = JWK::generate_ed25519().unwrap();
    let (app_did, _) = verification_method(&app_key);

    let (_, _, signed_terminal) = signed_cacao_token(
        &f.wallet,
        &app_did,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        Some(DelegationModeFact::Terminal),
        "tampernonce1",
    );

    // Rebuild the ReCap resource without delegationMode (strip) and with
    // "attenuable" (change) while keeping the original wallet signature.
    for mutated_mode in [None, Some(DelegationModeFact::Attenuable)] {
        let mut recap = RecapCapability::<serde_json::Value>::new();
        recap.with_action(
            f.kv_res.parse().unwrap(),
            "tinycloud.kv/get".parse().unwrap(),
            [BTreeMap::new()],
        );
        let recap = match mutated_mode {
            Some(m) => recap.with_delegation_mode(m),
            None => recap,
        };
        let mut tampered_payload = signed_terminal.payload().clone();
        tampered_payload.resources = Some(vec![(&recap).try_into().unwrap()]);
        let tampered_cacao = SiweCacao::new(
            tampered_payload,
            *signed_terminal.signature(),
            tinycloud_auth::cacaos::siwe_cacao::Header,
        );
        let token = TinyCloudDelegation::Cacao(Box::new(tampered_cacao))
            .encode()
            .unwrap();
        let err = must_err(f.db.delegate(parse_delegation(&token)).await);
        assert!(
            matches!(
                err,
                TxError::InvalidDelegation(delegation::DelegationError::InvalidSignature)
            ),
            "tampered mode ({mutated_mode:?}) must fail signature verification, got {err}"
        );
    }
}

#[tokio::test]
async fn chain_shapes_a_to_t_t_to_t_legacy_grandchild_multiparent_and_root_authority() {
    let f = Fixture::new(None).await;
    let seeder = JWK::generate_ed25519().unwrap();
    f.seed_kv_value(&seeder, b"value").await;

    let wallet_b = Wallet::from_seed(0x33);
    let k1 = JWK::generate_ed25519().unwrap();
    let (d1, _) = verification_method(&k1);
    let k2 = JWK::generate_ed25519().unwrap();
    let (d2, _) = verification_method(&k2);
    let k3 = JWK::generate_ed25519().unwrap();
    let (d3, _) = verification_method(&k3);

    // 1. A -> T (CACAO parent -> terminal CACAO child): T registration and
    // direct invocation succeed, T -> child is refused.
    let (a_token, a_cid, _) = signed_cacao_token(
        &f.wallet,
        &wallet_b.did,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        Some(DelegationModeFact::Attenuable),
        "atoten001",
    );
    must_ok(f.db.delegate(parse_delegation(&a_token)).await);
    let (t_from_a_token, t_from_a_cid, _) = signed_cacao_token(
        &wallet_b,
        &d1,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[a_cid],
        Some(DelegationModeFact::Terminal),
        "atoten002",
    );
    must_ok(f.db.delegate(parse_delegation(&t_from_a_token)).await);
    let inv = signed_invocation(&k1, &[(&f.kv_res, "tinycloud.kv/get")], &[t_from_a_cid]);
    must_ok(f.db.invoke::<MemoryStaging>(inv, HashMap::new()).await);

    // T -> T (terminal child of terminal parent) is refused.
    let (t_child_of_t, _) = signed_ucan_delegation(
        &k1,
        &d2,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[t_from_a_cid],
        true,
    );
    assert!(matches!(
        f.db.delegate(t_child_of_t).await,
        Err(TxError::InvalidDelegation(
            delegation::DelegationError::TerminalParentCannotRedelegate
        ))
    ));

    // 2. T -> legacy_child -> grandchild: simulate legacy_child stored before
    // upgrade; registering grandchild and invoking legacy_child both refuse.
    let (legacy_child, legacy_child_cid) = signed_ucan_delegation(
        &k1,
        &d2,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[t_from_a_cid],
        false,
    );
    f.insert_pre_upgrade_row(
        legacy_child.content_hash(),
        &d1,
        &d2,
        legacy_child.serialized_bytes(),
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[Hash::from(t_from_a_cid)],
        None,
    )
    .await;

    let (grandchild, grandchild_cid) = signed_ucan_delegation(
        &k2,
        &d3,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[legacy_child_cid],
        false,
    );
    assert!(matches!(
        f.db.delegate(grandchild).await,
        Err(TxError::InvalidDelegation(
            delegation::DelegationError::TerminalParentCannotRedelegate
        ))
    ));
    assert!(delegation::Entity::find_by_id(Hash::from(grandchild_cid))
        .one(&f.db.conn)
        .await
        .unwrap()
        .is_none());

    let legacy_inv =
        signed_invocation(&k2, &[(&f.kv_res, "tinycloud.kv/get")], &[legacy_child_cid]);
    assert!(matches!(
        f.db.invoke::<MemoryStaging>(legacy_inv, HashMap::new())
            .await,
        Err(TxStoreError::Tx(TxError::InvalidInvocation(
            invocation::InvocationError::TerminalParentCannotRedelegate
        )))
    ));

    // 3. Multi-parent: valid attenuable sibling + terminal parent (both orders)
    // refused on registration AND on invocation.
    let (valid_sibling_token, valid_sibling_cid, _) = signed_cacao_token(
        &f.wallet,
        &d1,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        Some(DelegationModeFact::Attenuable),
        "validsib01",
    );
    must_ok(f.db.delegate(parse_delegation(&valid_sibling_token)).await);
    for parents in [
        [valid_sibling_cid, t_from_a_cid],
        [t_from_a_cid, valid_sibling_cid],
    ] {
        let (child, child_cid) = signed_ucan_delegation(
            &k1,
            &d2,
            &[(&f.kv_res, "tinycloud.kv/get")],
            &parents,
            false,
        );
        assert!(matches!(
            f.db.delegate(child).await,
            Err(TxError::InvalidDelegation(
                delegation::DelegationError::TerminalParentCannotRedelegate
            ))
        ));
        assert!(delegation::Entity::find_by_id(Hash::from(child_cid))
            .one(&f.db.conn)
            .await
            .unwrap()
            .is_none());
    }

    let (valid_k2_token, valid_k2_cid, _) = signed_cacao_token(
        &f.wallet,
        &d2,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        Some(DelegationModeFact::Attenuable),
        "validsib02",
    );
    must_ok(f.db.delegate(parse_delegation(&valid_k2_token)).await);
    for parents in [
        [valid_k2_cid, legacy_child_cid],
        [legacy_child_cid, valid_k2_cid],
    ] {
        let inv = signed_invocation(&k2, &[(&f.kv_res, "tinycloud.kv/get")], &parents);
        assert!(matches!(
            f.db.invoke::<MemoryStaging>(inv, HashMap::new()).await,
            Err(TxStoreError::Tx(TxError::InvalidInvocation(
                invocation::InvocationError::TerminalParentCannotRedelegate
            )))
        ));
    }

    // 4. Root-authority signer cites terminal parent on registration -> refused
    // BEFORE root-authority shortcut.
    let (owner_child_token, owner_child_cid, _) = signed_cacao_token(
        &f.wallet,
        &d3,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[t_from_a_cid],
        None,
        "ownercite01",
    );
    assert!(matches!(
        f.db.delegate(parse_delegation(&owner_child_token)).await,
        Err(TxError::InvalidDelegation(
            delegation::DelegationError::TerminalParentCannotRedelegate
        ))
    ));
    assert!(delegation::Entity::find_by_id(Hash::from(owner_child_cid))
        .one(&f.db.conn)
        .await
        .unwrap()
        .is_none());

    // Root-authority invoker (a did:key space owner) citing a chain with a
    // terminal strict ancestor -> refused BEFORE root-authority shortcut.
    let key_owner = JWK::generate_ed25519().unwrap();
    let (key_owner_did, _) = verification_method(&key_owner);
    let owned_space: SpaceId = format!(
        "tinycloud:{}:own",
        key_owner_did.strip_prefix("did:").unwrap()
    )
    .parse()
    .unwrap();
    space::ActiveModel {
        id: Set(SpaceIdWrap(owned_space.clone())),
    }
    .insert(&f.db.conn)
    .await
    .unwrap();
    let owned_kv = owned_space
        .clone()
        .to_resource(
            "kv".parse().unwrap(),
            Some("a".parse().unwrap()),
            None,
            None,
        )
        .to_string();
    let root_inv = signed_invocation(
        &key_owner,
        &[(&owned_kv, "tinycloud.kv/get")],
        &[legacy_child_cid],
    );
    assert!(matches!(
        f.db.authorize_invocation(&root_inv.0, OffsetDateTime::now_utc())
            .await,
        Err(invocation::Error::InvalidInvocation(
            invocation::InvocationError::TerminalParentCannotRedelegate
        ))
    ));
}

#[tokio::test]
async fn revocation_of_terminal_cacao_and_ancestor_keep_existing_codes() {
    let f = Fixture::new(None).await;
    let seeder = JWK::generate_ed25519().unwrap();
    f.seed_kv_value(&seeder, b"v").await;

    // Revoke T directly -> DelegationRevoked.
    let k1 = JWK::generate_ed25519().unwrap();
    let (d1, _) = verification_method(&k1);
    let (t_token, t_cid, _) = signed_cacao_token(
        &f.wallet,
        &d1,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        Some(DelegationModeFact::Terminal),
        "revterm0001",
    );
    must_ok(f.db.delegate(parse_delegation(&t_token)).await);
    must_ok(
        f.db.revoke(signed_cacao_revocation(&f.wallet, t_cid, "revoket0001"))
            .await,
    );
    let inv = signed_invocation(&k1, &[(&f.kv_res, "tinycloud.kv/get")], &[t_cid]);
    assert!(matches!(
        f.db.authorize_invocation(&inv.0, OffsetDateTime::now_utc())
            .await,
        Err(invocation::Error::InvalidInvocation(
            invocation::InvocationError::DelegationRevoked(_)
        ))
    ));

    // In A -> T, revoke A -> direct invocation of T fails with DelegationAncestorRevoked.
    let wallet_b = Wallet::from_seed(0x44);
    let k2 = JWK::generate_ed25519().unwrap();
    let (d2, _) = verification_method(&k2);
    let (a_token, a_cid, _) = signed_cacao_token(
        &f.wallet,
        &wallet_b.did,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        Some(DelegationModeFact::Attenuable),
        "revanc00001",
    );
    must_ok(f.db.delegate(parse_delegation(&a_token)).await);
    let (t2_token, t2_cid, _) = signed_cacao_token(
        &wallet_b,
        &d2,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[a_cid],
        Some(DelegationModeFact::Terminal),
        "revanc00002",
    );
    must_ok(f.db.delegate(parse_delegation(&t2_token)).await);
    must_ok(
        f.db.revoke(signed_cacao_revocation(&f.wallet, a_cid, "revokea0001"))
            .await,
    );
    let inv2 = signed_invocation(&k2, &[(&f.kv_res, "tinycloud.kv/get")], &[t2_cid]);
    assert!(matches!(
        f.db.authorize_invocation(&inv2.0, OffsetDateTime::now_utc())
            .await,
        Err(invocation::Error::InvalidInvocation(
            invocation::InvocationError::DelegationAncestorRevoked { .. }
        ))
    ));
}

#[tokio::test]
async fn prelock_enforcement_single_repost_batch_and_core_read_write_invocations() {
    let f = Fixture::new(None).await;
    let seeder = JWK::generate_ed25519().unwrap();
    f.seed_kv_value(&seeder, b"orig").await;

    let app_key = JWK::generate_ed25519().unwrap();
    let (app_did, _) = verification_method(&app_key);
    let sub_key = JWK::generate_ed25519().unwrap();
    let (sub_did, _) = verification_method(&sub_key);

    // Store terminal CACAO T with get + put.
    let (t_token, t_cid, _) = signed_cacao_token(
        &f.wallet,
        &app_did,
        &[
            (&f.kv_res, "tinycloud.kv/get"),
            (&f.kv_res, "tinycloud.kv/put"),
        ],
        &[],
        Some(DelegationModeFact::Terminal),
        "prelock0001",
    );
    must_ok(f.db.delegate(parse_delegation(&t_token)).await);

    // Insert a legacy child of T to test repost & invocation under held locks.
    let (legacy_child, legacy_child_cid) = signed_ucan_delegation(
        &app_key,
        &sub_did,
        &[
            (&f.kv_res, "tinycloud.kv/get"),
            (&f.kv_res, "tinycloud.kv/put"),
        ],
        &[t_cid],
        false,
    );
    f.insert_pre_upgrade_row(
        legacy_child.content_hash(),
        &app_did,
        &sub_did,
        legacy_child.serialized_bytes(),
        &[
            (&f.kv_res, "tinycloud.kv/get"),
            (&f.kv_res, "tinycloud.kv/put"),
        ],
        &[Hash::from(t_cid)],
        None,
    )
    .await;

    // Hold EVERY lock simultaneously: space sequence, chain guards (exclusive),
    // and SQLite writer lock. Any path that tries to acquire any lock will hang
    // past the timeout.
    let _space_guards =
        f.db.acquire_space_sequence_guards(std::slice::from_ref(&f.space))
            .await;
    let _chain_guards = must_ok(
        f.db.acquire_chain_guards(&[Hash::from(t_cid), Hash::from(legacy_child_cid)])
            .await,
    );
    let _writer_guard = match &f.db.writer_lock {
        Some(lock) => Some(lock.lock().await),
        None => None,
    };

    // 1. Single delegate() citing stored T fails immediately without locks.
    let (new_child, _) = signed_ucan_delegation(
        &app_key,
        &sub_did,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[t_cid],
        false,
    );
    let res = tokio::time::timeout(std::time::Duration::from_secs(5), f.db.delegate(new_child))
        .await
        .expect("single delegate must refuse before locks");
    assert!(matches!(
        res,
        Err(TxError::InvalidDelegation(
            delegation::DelegationError::TerminalParentCannotRedelegate
        ))
    ));

    // 2. Reposting already-stored legacy_child refuses (NOT already-registered
    // success) and never waits for locks.
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        f.db.delegate(legacy_child.clone()),
    )
    .await
    .expect("repost of legacy child must refuse before locks");
    assert!(matches!(
        res,
        Err(TxError::InvalidDelegation(
            delegation::DelegationError::TerminalParentCannotRedelegate
        ))
    ));

    // 3. Batch [in-memory T2, child_of_T2] refuses before locks and stores neither.
    let (t2_token, t2_cid, _) = signed_cacao_token(
        &f.wallet,
        &app_did,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        Some(DelegationModeFact::Terminal),
        "prelockbat1",
    );
    let (child_of_t2, child_of_t2_cid) = signed_ucan_delegation(
        &app_key,
        &sub_did,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[t2_cid],
        false,
    );
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        f.db.delegate_batch(vec![parse_delegation(&t2_token), child_of_t2]),
    )
    .await
    .expect("in-memory batch parent must refuse before locks");
    assert!(matches!(
        res,
        Err(TxError::InvalidDelegation(
            delegation::DelegationError::TerminalParentCannotRedelegate
        ))
    ));
    assert!(delegation::Entity::find_by_id(Hash::from(t2_cid))
        .one(&f.db.conn)
        .await
        .unwrap()
        .is_none());
    assert!(delegation::Entity::find_by_id(Hash::from(child_of_t2_cid))
        .one(&f.db.conn)
        .await
        .unwrap()
        .is_none());

    // 4. Core read invocation (admitted AND public) refuses before chain/writer locks.
    let read_inv = signed_invocation(
        &sub_key,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[legacy_child_cid],
    );
    let admitted_read = AdmittedInvocation::admit(read_inv.clone(), 300)
        .await
        .unwrap();
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        f.db.invoke_read_admitted::<MemoryStaging>(
            &admitted_read,
            HashMap::new(),
            KvInvokeOptions::default(),
        ),
    )
    .await
    .expect("admitted read must refuse before chain/writer locks");
    assert!(matches!(
        res,
        Err(TxStoreError::Tx(TxError::InvalidInvocation(
            invocation::InvocationError::TerminalParentCannotRedelegate
        )))
    ));

    let res = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        f.db.invoke::<MemoryStaging>(read_inv, HashMap::new()),
    )
    .await
    .expect("public read must refuse before chain/writer locks");
    assert!(matches!(
        res,
        Err(TxStoreError::Tx(TxError::InvalidInvocation(
            invocation::InvocationError::TerminalParentCannotRedelegate
        )))
    ));

    // 5. Core write invocation (admitted) refuses before chain/object/space/writer locks.
    let write_inv = signed_invocation(
        &sub_key,
        &[(&f.kv_res, "tinycloud.kv/put")],
        &[legacy_child_cid],
    );
    let admitted_write = AdmittedInvocation::admit(write_inv, 300).await.unwrap();
    let mut stage = HashBuffer::new(Vec::new());
    stage.write_all(b"overwritten").await.unwrap();
    let mut inputs = HashMap::new();
    inputs.insert(
        (f.space.clone(), f.kv_path.clone()),
        (Metadata(BTreeMap::new()), stage),
    );
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        f.db.invoke_with_options_admitted::<MemoryStaging>(
            admitted_write,
            inputs,
            KvInvokeOptions::default(),
        ),
    )
    .await
    .expect("admitted write must refuse before locks");
    assert!(matches!(
        res,
        Err(TxStoreError::Tx(TxError::InvalidInvocation(
            invocation::InvocationError::TerminalParentCannotRedelegate
        )))
    ));
}

#[tokio::test]
async fn boot_reindex_handles_plaintext_encrypted_malformed_and_interrupted_restart() {
    // Part A: Encrypted DB with pre-upgrade terminal CACAO, malformed-mode
    // CACAO, and normal attenuable CACAO.
    let encryption = ColumnEncryption::new([0x7a; 32]);
    let f = Fixture::new(Some(encryption.clone())).await;
    let seeder = JWK::generate_ed25519().unwrap();
    f.seed_kv_value(&seeder, b"enc-secret").await;

    let k_term = JWK::generate_ed25519().unwrap();
    let (d_term, _) = verification_method(&k_term);
    let k_term_child = JWK::generate_ed25519().unwrap();
    let (d_term_child, _) = verification_method(&k_term_child);
    let k_bad = JWK::generate_ed25519().unwrap();
    let (d_bad, _) = verification_method(&k_bad);
    let k_bad_child = JWK::generate_ed25519().unwrap();
    let (d_bad_child, _) = verification_method(&k_bad_child);
    let k_ok = JWK::generate_ed25519().unwrap();
    let (d_ok, _) = verification_method(&k_ok);
    let k_ok_child = JWK::generate_ed25519().unwrap();
    let (d_ok_child, _) = verification_method(&k_ok_child);

    // Pre-upgrade encrypted terminal CACAO (facts = None) + its legacy child.
    let (t_token, t_cid, _) = signed_cacao_token(
        &f.wallet,
        &d_term,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        Some(DelegationModeFact::Terminal),
        "reidxterm01",
    );
    let (_, t_bytes) = TinyCloudDelegation::decode(&t_token).unwrap();
    f.insert_pre_upgrade_row(
        Hash::from(t_cid),
        &f.wallet.did,
        &d_term,
        &t_bytes,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        Some(&encryption),
    )
    .await;
    let (t_child, t_child_cid) = signed_ucan_delegation(
        &k_term,
        &d_term_child,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[t_cid],
        false,
    );
    f.insert_pre_upgrade_row(
        t_child.content_hash(),
        &d_term,
        &d_term_child,
        t_child.serialized_bytes(),
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[Hash::from(t_cid)],
        Some(&encryption),
    )
    .await;

    // Pre-upgrade malformed-mode CACAO (facts = None) + its legacy child.
    let (bad_bytes, bad_hash, bad_cid) = signed_cacao_with_raw_recap_tail(
        &f.wallet,
        &d_bad,
        &[(&f.kv_res, "tinycloud.kv/get")],
        r#""xyz.tinycloud.policy/delegationMode":"bogus""#,
        "reidxbad001",
    );
    f.insert_pre_upgrade_row(
        bad_hash,
        &f.wallet.did,
        &d_bad,
        &bad_bytes,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        Some(&encryption),
    )
    .await;
    let (bad_child, bad_child_cid) = signed_ucan_delegation(
        &k_bad,
        &d_bad_child,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[bad_cid],
        false,
    );
    f.insert_pre_upgrade_row(
        bad_child.content_hash(),
        &d_bad,
        &d_bad_child,
        bad_child.serialized_bytes(),
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[bad_hash],
        Some(&encryption),
    )
    .await;

    // Pre-upgrade normal attenuable CACAO (absent field) + its child.
    let (ok_token, ok_cid, _) = signed_cacao_token(
        &f.wallet,
        &d_ok,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        None,
        "reidxok0001",
    );
    let (_, ok_bytes) = TinyCloudDelegation::decode(&ok_token).unwrap();
    f.insert_pre_upgrade_row(
        Hash::from(ok_cid),
        &f.wallet.did,
        &d_ok,
        &ok_bytes,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        Some(&encryption),
    )
    .await;
    let (ok_child, ok_child_cid) = signed_ucan_delegation(
        &k_ok,
        &d_ok_child,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[ok_cid],
        false,
    );
    f.insert_pre_upgrade_row(
        ok_child.content_hash(),
        &d_ok,
        &d_ok_child,
        ok_child.serialized_bytes(),
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[Hash::from(ok_cid)],
        Some(&encryption),
    )
    .await;

    // Reopen database (boot reindex runs synchronously before returning).
    let reopened = SpaceDatabase::new_with_encryption(
        sea_orm::Database::connect(&f.url).await.unwrap(),
        MemoryStore::default(),
        StaticSecret::new(vec![0x55; 32]).unwrap(),
        Some(encryption.clone()),
    )
    .await
    .expect("boot must succeed despite stored malformed-mode CACAO");

    // 1. Terminal CACAO reindexed: direct invoke OK; old child invoke & repost refused.
    let t_row = delegation::Entity::find_by_id(Hash::from(t_cid))
        .one(&reopened.conn)
        .await
        .unwrap()
        .unwrap();
    assert!(delegation::parent_is_terminal(&t_row));
    assert!(!delegation::delegation_mode_is_invalid(&t_row));
    let direct_inv = signed_invocation(&k_term, &[(&f.kv_res, "tinycloud.kv/get")], &[t_cid]);
    reopened
        .authorize_invocation(&direct_inv.0, OffsetDateTime::now_utc())
        .await
        .unwrap();
    let old_child_inv = signed_invocation(
        &k_term_child,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[t_child_cid],
    );
    assert!(matches!(
        reopened
            .authorize_invocation(&old_child_inv.0, OffsetDateTime::now_utc())
            .await,
        Err(invocation::Error::InvalidInvocation(
            invocation::InvocationError::TerminalParentCannotRedelegate
        ))
    ));
    assert!(matches!(
        reopened.delegate(t_child).await,
        Err(TxError::InvalidDelegation(
            delegation::DelegationError::TerminalParentCannotRedelegate
        ))
    ));

    // 2. Malformed-mode CACAO marked terminal AND refused: direct invoke,
    // descendant invoke, and new child registration all fail.
    let bad_row = delegation::Entity::find_by_id(bad_hash)
        .one(&reopened.conn)
        .await
        .unwrap()
        .unwrap();
    assert!(delegation::parent_is_terminal(&bad_row));
    assert!(delegation::delegation_mode_is_invalid(&bad_row));
    let bad_direct = signed_invocation(&k_bad, &[(&f.kv_res, "tinycloud.kv/get")], &[bad_cid]);
    assert!(matches!(
        reopened
            .authorize_invocation(&bad_direct.0, OffsetDateTime::now_utc())
            .await,
        Err(invocation::Error::InvalidInvocation(
            invocation::InvocationError::InvalidDelegationMode
        ))
    ));
    let bad_desc = signed_invocation(
        &k_bad_child,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[bad_child_cid],
    );
    assert!(matches!(
        reopened
            .authorize_invocation(&bad_desc.0, OffsetDateTime::now_utc())
            .await,
        Err(invocation::Error::InvalidInvocation(
            invocation::InvocationError::TerminalParentCannotRedelegate
        ))
    ));
    let (new_bad_child, _) = signed_ucan_delegation(
        &k_bad,
        &d_bad_child,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[bad_cid],
        false,
    );
    assert!(matches!(
        reopened.delegate(new_bad_child).await,
        Err(TxError::InvalidDelegation(
            delegation::DelegationError::TerminalParentCannotRedelegate
        ))
    ));

    // 3. Normal attenuable row & its child are marked explicitly "attenuable",
    // never treated as terminal (including by older-node rollback checks), and
    // remain unaffected.
    let ok_row = delegation::Entity::find_by_id(Hash::from(ok_cid))
        .one(&reopened.conn)
        .await
        .unwrap()
        .unwrap();
    assert!(!delegation::parent_is_terminal(&ok_row));
    assert!(!delegation::delegation_mode_is_invalid(&ok_row));
    assert_eq!(
        ok_row
            .facts
            .as_ref()
            .and_then(|crate::types::Facts(m)| m.get(crate::util::DelegationMode::FACT_KEY))
            .and_then(|v| v.as_str()),
        Some("attenuable"),
        "scanned legacy row must be marked explicitly attenuable so future boots skip it"
    );
    let ok_inv = signed_invocation(
        &k_ok_child,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[ok_child_cid],
    );
    reopened
        .authorize_invocation(&ok_inv.0, OffsetDateTime::now_utc())
        .await
        .unwrap();

    // 4. F2 stored-row readers tolerate the malformed-mode row without failing
    // listing or purge, while keeping it unusable for authorization/renewal.
    let listed = must_ok(
        get_valid_delegations::<_, MemoryStore, StaticSecret>(
            &reopened.conn,
            &f.space,
            Some(&encryption),
        )
        .await,
    );
    assert!(
        listed.contains_key(&bad_hash),
        "listing a space with a malformed stored row must succeed and remain listable"
    );
    assert_eq!(
        listed[&bad_hash].0.delegation_mode,
        crate::util::DelegationMode::Invalid
    );
    assert!(listed.contains_key(&Hash::from(ok_cid)));

    let (_, loaded_bad) = reopened
        .load_signed_delegation(bad_cid)
        .await
        .expect("load_signed_delegation must tolerate malformed stored row")
        .expect("malformed row must exist");
    assert_eq!(
        loaded_bad.0.delegation_mode,
        crate::util::DelegationMode::Invalid
    );

    let (_, collector_bad) =
        crate::resource_purge_dependencies::collector::decode(&bad_row, Some(&encryption))
            .expect("resource_purge collector must tolerate malformed stored row");
    assert_eq!(
        collector_bad.delegation_mode,
        crate::util::DelegationMode::Invalid
    );

    let purge_targets =
        crate::space_purge_records::policy::inventory_authorization_targets(&bad_bytes)
            .expect("space_purge policy must tolerate malformed stored row");
    assert_eq!(
        purge_targets,
        vec![crate::space_purge_records::policy::PolicyTarget::Space(
            f.space.to_string()
        )]
    );

    // Renewal registration must refuse a malformed stored original.
    let renew_res = format!("urn:cid:{bad_cid}");
    let (renew_lease_tok, _, _) = signed_cacao_token(
        &f.wallet,
        &reopened.secrets.node_did(),
        &[(&renew_res, "tinycloud.delegation/renew")],
        &[],
        None,
        "renewbad001",
    );
    let renew_lease = parse_delegation(&renew_lease_tok);
    assert!(matches!(
        crate::renewal::preverify_lease_original(&reopened.conn, &renew_lease, Some(&encryption))
            .await,
        Err(crate::renewal::RenewalStoreError::InvalidInput)
    ));

    // 5. F1: Second boot scans 0 rows (both previously indexed rows and newly
    // saved rows already carry `delegationMode` in `facts`).
    let stats = delegation::reindex_cacao_modes(&reopened.conn, Some(&encryption))
        .await
        .unwrap();
    assert!(stats.completed);
    assert_eq!(stats.scanned, 0, "second boot must scan 0 rows");
    assert_eq!(stats.reindexed_terminal, 0);
    assert_eq!(stats.marked_attenuable, 0);
    assert_eq!(stats.marked_invalid, 0);

    let fresh_key = JWK::generate_ed25519().unwrap();
    let (fresh_did, _) = verification_method(&fresh_key);
    let (fresh_tok, _, _) = signed_cacao_token(
        &f.wallet,
        &fresh_did,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        None,
        "freshsave01",
    );
    must_ok(reopened.delegate(parse_delegation(&fresh_tok)).await);
    let stats_after_save = delegation::reindex_cacao_modes(&reopened.conn, Some(&encryption))
        .await
        .unwrap();
    assert!(stats_after_save.completed);
    assert_eq!(
        stats_after_save.scanned, 0,
        "newly saved rows must already be indexed and skipped on next boot"
    );

    // Part B: Plaintext multi-page interrupted reindex + restart completes
    // remaining pages before SpaceDatabase::new returns.
    let f_plain = Fixture::new(None).await;
    let mut inserted_terminals: Vec<(Hash, Cid, JWK, String)> = Vec::new();
    // Insert 140 pre-upgrade terminal CACAOs (> 128 PAGE_SIZE) so reindex spans
    // at least 2 pages regardless of hash ordering.
    for i in 0..140usize {
        let holder = JWK::generate_ed25519().unwrap();
        let (holder_did, _) = verification_method(&holder);
        let (tok, cid, _) = signed_cacao_token(
            &f_plain.wallet,
            &holder_did,
            &[(&f_plain.kv_res, "tinycloud.kv/get")],
            &[],
            Some(DelegationModeFact::Terminal),
            &format!("multipage{i:04}"),
        );
        let (_, bytes) = TinyCloudDelegation::decode(&tok).unwrap();
        f_plain
            .insert_pre_upgrade_row(
                Hash::from(cid),
                &f_plain.wallet.did,
                &holder_did,
                &bytes,
                &[(&f_plain.kv_res, "tinycloud.kv/get")],
                &[],
                None,
            )
            .await;
        inserted_terminals.push((Hash::from(cid), cid, holder, holder_did));
    }

    // Simulate interruption after page 1 (128 rows).
    let partial = delegation::reindex_cacao_modes_bounded(&f_plain.db.conn, None, Some(1))
        .await
        .unwrap();
    assert!(!partial.completed, "1-page bounded run must stop early");
    assert_eq!(partial.scanned, 128);
    assert_eq!(partial.reindexed_terminal, 128);

    // Confirm 12 rows on page 2 are not yet marked.
    let unmarked_before: usize = delegation::Entity::find()
        .all(&f_plain.db.conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|row| !delegation::parent_is_terminal(row))
        .count();
    assert_eq!(unmarked_before, 12);

    // Restart: SpaceDatabase::new runs reindex to completion before returning.
    let restarted = SpaceDatabase::new(
        sea_orm::Database::connect(&f_plain.url).await.unwrap(),
        MemoryStore::default(),
        StaticSecret::new(vec![0x55; 32]).unwrap(),
    )
    .await
    .unwrap();
    let unmarked_after: usize = delegation::Entity::find()
        .all(&restarted.conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|row| !delegation::parent_is_terminal(row))
        .count();
    assert_eq!(
        unmarked_after, 0,
        "all 140 rows must be reindexed on restart"
    );
    let second_boot = delegation::reindex_cacao_modes(&restarted.conn, None)
        .await
        .unwrap();
    assert!(second_boot.completed);
    assert_eq!(second_boot.scanned, 0);

    // Pick a row from both ends of sorted ID order and confirm children are refused.
    inserted_terminals.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));
    let sub = JWK::generate_ed25519().unwrap();
    let (sub_did, _) = verification_method(&sub);
    for (_, cid, holder, _) in [
        inserted_terminals.first().unwrap(),
        inserted_terminals.last().unwrap(),
    ] {
        let (child, _) = signed_ucan_delegation(
            holder,
            &sub_did,
            &[(&f_plain.kv_res, "tinycloud.kv/get")],
            &[*cid],
            false,
        );
        assert!(matches!(
            restarted.delegate(child).await,
            Err(TxError::InvalidDelegation(
                delegation::DelegationError::TerminalParentCannotRedelegate
            ))
        ));
    }
}
