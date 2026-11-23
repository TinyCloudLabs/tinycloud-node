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

#[allow(clippy::too_many_arguments)]
async fn insert_pre_upgrade_row_on<C: ConnectionTrait>(
    conn: &C,
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
        .insert(conn)
        .await
        .ok();
    }
    let stored = crate::encryption::maybe_encrypt(
        encryption,
        plaintext,
        crate::encryption::RowBinding::new("delegation", "serialization", &[&Vec::<u8>::from(id)]),
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
    .insert(conn)
    .await
    .unwrap();
    delegation_cid_alias::ActiveModel {
        id: Set(id),
        canonical: Set(id),
        encrypted: Set(encryption.is_some()),
    }
    .insert(conn)
    .await
    .unwrap();
    for (resource, ability) in grants {
        abilities::Entity::insert(abilities::ActiveModel {
            delegation: Set(id),
            resource: Set(resource.parse().unwrap()),
            ability: Set((*ability).to_owned().try_into().unwrap()),
            caveats: Set(Default::default()),
        })
        .exec(conn)
        .await
        .unwrap();
    }
    for parent in parents {
        parent_delegations::ActiveModel {
            child: Set(id),
            parent: Set(*parent),
        }
        .insert(conn)
        .await
        .unwrap();
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
        insert_pre_upgrade_row_on(
            &self.db.conn,
            id,
            delegator,
            delegatee,
            plaintext,
            grants,
            parents,
            encryption,
        )
        .await;
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

    // Side table carries terminal mode (written atomically in the same
    // transaction as the delegation row), and facts keeps "terminal" for
    // rollback compatibility with older nodes.
    let mode_row = delegation_mode::Entity::find_by_id(Hash::from(t_cid))
        .one(&f.db.conn)
        .await
        .unwrap()
        .expect("delegation_mode row must be written in the same transaction as delegation");
    assert_eq!(
        delegation_mode::StoredDelegationMode::from_db_str(&mode_row.mode),
        delegation_mode::StoredDelegationMode::Terminal
    );
    let row = delegation::Entity::find_by_id(Hash::from(t_cid))
        .one(&f.db.conn)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.facts
            .as_ref()
            .and_then(|crate::types::Facts(m)| m.get(crate::util::DelegationMode::FACT_KEY))
            .and_then(|v| v.as_str()),
        Some("terminal")
    );

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
        f.db.delegate_batch(vec![parse_delegation(&t2_token), child_of_t2.clone()]),
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

    // 6. Reverse-order core batch [child_of_T2, T2] is refused with
    // MissingParents and stores neither row.
    drop(_writer_guard);
    drop(_chain_guards);
    drop(_space_guards);
    let res_rev =
        f.db.delegate_batch(vec![child_of_t2, parse_delegation(&t2_token)])
            .await;
    assert!(matches!(
        res_rev,
        Err(TxError::InvalidDelegation(
            delegation::DelegationError::MissingParents
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

    // 1. Terminal CACAO backfilled into side table without rewriting the
    // historical delegation row (`facts` stays `None`): direct invoke OK; old
    // child invoke & repost refused.
    let t_row = delegation::Entity::find_by_id(Hash::from(t_cid))
        .one(&reopened.conn)
        .await
        .unwrap()
        .unwrap();
    assert!(
        t_row.facts.is_none(),
        "boot backfill must never rewrite delegation.facts on historical rows"
    );
    let t_mode = delegation_mode::Entity::find_by_id(Hash::from(t_cid))
        .one(&reopened.conn)
        .await
        .unwrap()
        .expect("terminal CACAO must have a delegation_mode row");
    assert_eq!(
        delegation_mode::StoredDelegationMode::from_db_str(&t_mode.mode),
        delegation_mode::StoredDelegationMode::Terminal
    );
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

    // 2. Malformed-mode CACAO marked invalid in side table (delegation row
    // untouched): direct invoke, descendant invoke, and new child registration
    // all fail.
    let bad_row = delegation::Entity::find_by_id(bad_hash)
        .one(&reopened.conn)
        .await
        .unwrap()
        .unwrap();
    assert!(
        bad_row.facts.is_none(),
        "boot backfill must never rewrite delegation.facts on malformed historical rows"
    );
    let bad_mode = delegation_mode::Entity::find_by_id(bad_hash)
        .one(&reopened.conn)
        .await
        .unwrap()
        .expect("malformed CACAO must have a delegation_mode row");
    assert_eq!(
        delegation_mode::StoredDelegationMode::from_db_str(&bad_mode.mode),
        delegation_mode::StoredDelegationMode::Invalid
    );
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
    // Core delegation_status also denies an invalid-marked proof and a
    // terminal-ancestor proof (defense in depth in control_proof_decision_at).
    assert_eq!(
        must_ok(
            reopened
                .delegation_status(Hash::from(ok_cid), &d_bad, &[bad_cid])
                .await
        ),
        None
    );
    assert_eq!(
        must_ok(
            reopened
                .delegation_status(Hash::from(ok_cid), &d_term_child, &[t_child_cid])
                .await
        ),
        None
    );

    // 3. Normal attenuable row & its child are marked "attenuable" in the
    // side table while leaving `delegation.facts` untouched (`None`), and
    // remain unaffected.
    let ok_row = delegation::Entity::find_by_id(Hash::from(ok_cid))
        .one(&reopened.conn)
        .await
        .unwrap()
        .unwrap();
    assert!(
        ok_row.facts.is_none(),
        "boot backfill must never rewrite delegation.facts on attenuable historical rows"
    );
    let ok_mode = delegation_mode::Entity::find_by_id(Hash::from(ok_cid))
        .one(&reopened.conn)
        .await
        .unwrap()
        .expect("attenuable CACAO must have a delegation_mode row");
    assert_eq!(
        delegation_mode::StoredDelegationMode::from_db_str(&ok_mode.mode),
        delegation_mode::StoredDelegationMode::Attenuable
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

    // Renewal registration must refuse a malformed stored original. Assert the
    // original row exists so InvalidInput proves mode refusal, not a missing row.
    assert!(
        delegation::Entity::find_by_id(bad_hash)
            .one(&reopened.conn)
            .await
            .unwrap()
            .is_some(),
        "malformed original row must exist before testing renewal refusal"
    );
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

    // 5. F1: Second boot scans 0 rows (both previously backfilled rows and
    // newly saved rows already carry a `delegation_mode` row).
    let stats = delegation_mode::backfill(&reopened.conn, Some(&encryption))
        .await
        .unwrap();
    assert!(stats.completed);
    assert_eq!(stats.scanned, 0, "second boot must scan 0 rows");
    assert_eq!(stats.reindexed_terminal, 0);
    assert_eq!(stats.marked_attenuable, 0);
    assert_eq!(stats.marked_invalid, 0);

    let fresh_key = JWK::generate_ed25519().unwrap();
    let (fresh_did, _) = verification_method(&fresh_key);
    let (fresh_tok, fresh_cid, _) = signed_cacao_token(
        &f.wallet,
        &fresh_did,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        None,
        "freshsave01",
    );
    must_ok(reopened.delegate(parse_delegation(&fresh_tok)).await);
    // Same-tx mark row exists immediately, and `delegation.facts` stays None.
    let fresh_mode = delegation_mode::Entity::find_by_id(Hash::from(fresh_cid))
        .one(&reopened.conn)
        .await
        .unwrap()
        .expect("newly saved attenuable delegation must write delegation_mode in same tx");
    assert_eq!(
        delegation_mode::StoredDelegationMode::from_db_str(&fresh_mode.mode),
        delegation_mode::StoredDelegationMode::Attenuable
    );
    let fresh_row = delegation::Entity::find_by_id(Hash::from(fresh_cid))
        .one(&reopened.conn)
        .await
        .unwrap()
        .unwrap();
    assert!(
        fresh_row.facts.is_none(),
        "newly saved attenuable CACAO keeps facts = None"
    );
    let stats_after_save = delegation_mode::backfill(&reopened.conn, Some(&encryption))
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
    let partial = delegation_mode::backfill_bounded(&f_plain.db.conn, None, Some(1))
        .await
        .unwrap();
    assert!(!partial.completed, "1-page bounded run must stop early");
    assert_eq!(partial.scanned, 128);
    assert_eq!(partial.reindexed_terminal, 128);

    // Confirm 12 rows on page 2 are not yet marked in `delegation_mode`.
    let marked_before = delegation_mode::Entity::find()
        .all(&f_plain.db.conn)
        .await
        .unwrap()
        .len();
    assert_eq!(marked_before, 128);

    // Restart: SpaceDatabase::new runs reindex to completion before returning.
    let restarted = SpaceDatabase::new(
        sea_orm::Database::connect(&f_plain.url).await.unwrap(),
        MemoryStore::default(),
        StaticSecret::new(vec![0x55; 32]).unwrap(),
    )
    .await
    .unwrap();
    let marked_after: usize = delegation_mode::Entity::find()
        .all(&restarted.conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|row| {
            delegation_mode::StoredDelegationMode::from_db_str(&row.mode)
                == delegation_mode::StoredDelegationMode::Terminal
        })
        .count();
    assert_eq!(
        marked_after, 140,
        "all 140 rows must be backfilled in delegation_mode on restart"
    );
    let second_boot = delegation_mode::backfill(&restarted.conn, None)
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

/// TC-3810 (Bobbie checklist a, b, c):
/// (a) Missing `delegation_mode` mark row is always fail-closed: unmarked rows
///     derive their mode on read from the stored signed bytes, and decryption
///     or parse failures map to `Invalid` (never `Attenuable`).
/// (b) `delegate()` writes `delegation_mode` in the same transaction as
///     `delegation` (for both accepted writes and rolled-back/refused writes).
/// (c) Space purge cleans up `delegation_mode` rows alongside `delegation`.
#[tokio::test]
async fn unmarked_rows_fail_closed_same_tx_write_and_purge_cleanup() {
    let encryption = ColumnEncryption::new([0x4c; 32]);
    let f = Fixture::new(Some(encryption.clone())).await;
    let seeder = JWK::generate_ed25519().unwrap();
    f.seed_kv_value(&seeder, b"side-table-secret").await;

    let k_term = JWK::generate_ed25519().unwrap();
    let (d_term, _) = verification_method(&k_term);
    let k_bad = JWK::generate_ed25519().unwrap();
    let (d_bad, _) = verification_method(&k_bad);
    let k_enc = JWK::generate_ed25519().unwrap();
    let (d_enc, _) = verification_method(&k_enc);
    let k_corrupt = JWK::generate_ed25519().unwrap();
    let (d_corrupt, _) = verification_method(&k_corrupt);
    let k_sub = JWK::generate_ed25519().unwrap();
    let (d_sub, _) = verification_method(&k_sub);

    // 1. Register a terminal CACAO via normal delegate(), verify mark row
    // exists in the same tx, then DELETE its mark row to simulate an unmarked
    // row (e.g. crashed/skipped backfill or manual row deletion).
    let (t_tok, t_cid, _) = signed_cacao_token(
        &f.wallet,
        &d_term,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        Some(DelegationModeFact::Terminal),
        "unmarkterm1",
    );
    must_ok(f.db.delegate(parse_delegation(&t_tok)).await);
    let t_hash = Hash::from(t_cid);
    assert_eq!(
        delegation_mode::Entity::find_by_id(t_hash)
            .one(&f.db.conn)
            .await
            .unwrap()
            .map(|r| r.mode),
        Some("terminal".to_string())
    );
    delegation_mode::Entity::delete_by_id(t_hash)
        .exec(&f.db.conn)
        .await
        .unwrap();
    assert!(delegation_mode::Entity::find_by_id(t_hash)
        .one(&f.db.conn)
        .await
        .unwrap()
        .is_none());

    // Unmarked terminal CACAO: direct use still works, child registration and
    // child invocation STILL refuse (derive-on-read from signed bytes).
    let direct_inv = signed_invocation(&k_term, &[(&f.kv_res, "tinycloud.kv/get")], &[t_cid]);
    must_ok(
        f.db.invoke::<MemoryStaging>(direct_inv, HashMap::new())
            .await,
    );
    let (child_of_unmarked_t, child_of_unmarked_t_cid) = signed_ucan_delegation(
        &k_term,
        &d_sub,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[t_cid],
        false,
    );
    assert!(matches!(
        f.db.delegate(child_of_unmarked_t.clone()).await,
        Err(TxError::InvalidDelegation(
            delegation::DelegationError::TerminalParentCannotRedelegate
        ))
    ));
    // Refused delegation wrote neither `delegation` nor `delegation_mode`.
    assert!(
        delegation::Entity::find_by_id(Hash::from(child_of_unmarked_t_cid))
            .one(&f.db.conn)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        delegation_mode::Entity::find_by_id(Hash::from(child_of_unmarked_t_cid))
            .one(&f.db.conn)
            .await
            .unwrap()
            .is_none()
    );
    // Insert a pre-upgrade legacy child under the unmarked terminal parent ->
    // invocation and delegation_status must refuse.
    f.insert_pre_upgrade_row(
        child_of_unmarked_t.content_hash(),
        &d_term,
        &d_sub,
        child_of_unmarked_t.serialized_bytes(),
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[t_hash],
        Some(&encryption),
    )
    .await;
    let inv_via_unmarked_t = signed_invocation(
        &k_sub,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[child_of_unmarked_t_cid],
    );
    assert!(matches!(
        f.db.invoke::<MemoryStaging>(inv_via_unmarked_t, HashMap::new())
            .await,
        Err(TxStoreError::Tx(TxError::InvalidInvocation(
            invocation::InvocationError::TerminalParentCannotRedelegate
        )))
    ));
    assert_eq!(
        must_ok(
            f.db.delegation_status(t_hash, &d_sub, &[child_of_unmarked_t_cid])
                .await
        ),
        None
    );

    // 2. Unmarked malformed-mode CACAO (encrypted, NO delegation_mode row):
    // direct invocation refused with InvalidDelegationMode, child refused with
    // TerminalParentCannotRedelegate.
    let (bad_bytes, bad_hash, bad_cid) = signed_cacao_with_raw_recap_tail(
        &f.wallet,
        &d_bad,
        &[(&f.kv_res, "tinycloud.kv/get")],
        r#""xyz.tinycloud.policy/delegationMode":"bogus""#,
        "unmarkbad01",
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
    let bad_direct = signed_invocation(&k_bad, &[(&f.kv_res, "tinycloud.kv/get")], &[bad_cid]);
    assert!(matches!(
        f.db.invoke::<MemoryStaging>(bad_direct, HashMap::new())
            .await,
        Err(TxStoreError::Tx(TxError::InvalidInvocation(
            invocation::InvocationError::InvalidDelegationMode
        )))
    ));
    let (bad_child, _) = signed_ucan_delegation(
        &k_bad,
        &d_sub,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[bad_cid],
        false,
    );
    assert!(matches!(
        f.db.delegate(bad_child).await,
        Err(TxError::InvalidDelegation(
            delegation::DelegationError::TerminalParentCannotRedelegate
        ))
    ));

    // 3. Unmarked encrypted CACAO whose decryption FAILS (wrong/missing key):
    // derive-on-read fails closed to `Invalid`, NEVER `Attenuable`.
    let (enc_tok, enc_cid, _) = signed_cacao_token(
        &f.wallet,
        &d_enc,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        Some(DelegationModeFact::Attenuable),
        "unmarkenc01",
    );
    let (_, enc_bytes) = TinyCloudDelegation::decode(&enc_tok).unwrap();
    let enc_hash = Hash::from(enc_cid);
    f.insert_pre_upgrade_row(
        enc_hash,
        &f.wallet.did,
        &d_enc,
        &enc_bytes,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        Some(&encryption),
    )
    .await;
    // Load the graph WITHOUT the encryption key (decryption fails).
    let wrong_key_graph =
        crate::auth_graph::AuthGraphSnapshot::load_with_encryption(&f.db.conn, &[enc_hash], None)
            .await
            .unwrap();
    assert_eq!(
        wrong_key_graph.delegation_mode(&enc_hash),
        Some(delegation_mode::StoredDelegationMode::Invalid),
        "undecryptable unmarked row must fail closed to Invalid"
    );
    let wrong_key_err = invocation::preflight_terminal_ancestors(&f.db.conn, &[enc_cid], None)
        .await
        .unwrap_err();
    assert!(matches!(
        wrong_key_err,
        invocation::Error::InvalidInvocation(invocation::InvocationError::InvalidDelegationMode)
    ));

    // 4. Unmarked unparseable plaintext row: fails closed as non-attenuable
    // (`Terminal`), so it can never be cited as a parent for redelegation.
    let corrupt_bytes = b"not-a-valid-ucan-or-cacao-payload".to_vec();
    let corrupt_hash = crate::hash::hash(&corrupt_bytes);
    let corrupt_cid = corrupt_hash.to_cid(0x55);
    f.insert_pre_upgrade_row(
        corrupt_hash,
        &f.wallet.did,
        &d_corrupt,
        &corrupt_bytes,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[],
        None,
    )
    .await;
    let corrupt_graph = crate::auth_graph::AuthGraphSnapshot::load_with_encryption(
        &f.db.conn,
        &[corrupt_hash],
        Some(&encryption),
    )
    .await
    .unwrap();
    assert_eq!(
        corrupt_graph.delegation_mode(&corrupt_hash),
        Some(delegation_mode::StoredDelegationMode::Terminal),
        "unparseable unmarked plaintext row must fail closed to Terminal (non-attenuable)"
    );
    let (corrupt_child, _) = signed_ucan_delegation(
        &k_corrupt,
        &d_sub,
        &[(&f.kv_res, "tinycloud.kv/get")],
        &[corrupt_cid],
        false,
    );
    assert!(matches!(
        f.db.delegate(corrupt_child).await,
        Err(TxError::InvalidDelegation(
            delegation::DelegationError::TerminalParentCannotRedelegate
        ))
    ));

    // 5. Space purge record deletion cleans up `delegation_mode` rows
    // alongside `delegation` rows (even when SQLite foreign_keys is OFF).
    let backfilled = delegation_mode::backfill(&f.db.conn, Some(&encryption))
        .await
        .unwrap();
    assert!(backfilled.completed);
    assert!(delegation_mode::Entity::find_by_id(t_hash)
        .one(&f.db.conn)
        .await
        .unwrap()
        .is_some());
    let deleted: HashSet<Hash> = [t_hash].into_iter().collect();
    let tx = f.db.conn.begin().await.unwrap();
    crate::space_purge_records::remove_records_for_test(&tx, &deleted)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(
        delegation_mode::Entity::find_by_id(t_hash)
            .one(&f.db.conn)
            .await
            .unwrap()
            .is_none(),
        "space purge must remove delegation_mode rows for deleted delegations"
    );
}

/// TC-3810 (required test): a REAL legacy signed DAG-CBOR CACAO row that is
/// attenuable by its signed statement, stored with NO `delegation_mode` row,
/// resolves to `Attenuable` on the read path (before backfill) AND after boot
/// backfill, and can parent a redelegation and authorize its child invocation.
#[tokio::test]
async fn real_legacy_attenuable_cacao_unmarked_read_path_and_after_backfill_can_parent_redelegation(
) {
    for encrypted in [false, true] {
        let encryption = encrypted.then(|| ColumnEncryption::new([0x6d; 32]));
        let f = Fixture::new(encryption.clone()).await;
        let seeder = JWK::generate_ed25519().unwrap();
        f.seed_kv_value(&seeder, b"legacy-attenuable-ok").await;

        let holder = JWK::generate_ed25519().unwrap();
        let (holder_did, _) = verification_method(&holder);
        let sub1 = JWK::generate_ed25519().unwrap();
        let (sub1_did, _) = verification_method(&sub1);
        let sub2 = JWK::generate_ed25519().unwrap();
        let (sub2_did, _) = verification_method(&sub2);

        // Insert a real wallet-signed DAG-CBOR CACAO (absent delegationMode ->
        // attenuable by its signed statement) with NO `delegation_mode` row.
        let (cacao_tok, cacao_cid, _) = signed_cacao_token(
            &f.wallet,
            &holder_did,
            &[(&f.kv_res, "tinycloud.kv/get")],
            &[],
            None,
            if encrypted {
                "legattenc01"
            } else {
                "legattpln01"
            },
        );
        let (_, cacao_bytes) = TinyCloudDelegation::decode(&cacao_tok).unwrap();
        let cacao_hash = Hash::from(cacao_cid);
        f.insert_pre_upgrade_row(
            cacao_hash,
            &f.wallet.did,
            &holder_did,
            &cacao_bytes,
            &[(&f.kv_res, "tinycloud.kv/get")],
            &[],
            encryption.as_ref(),
        )
        .await;
        assert!(
            delegation_mode::Entity::find_by_id(cacao_hash)
                .one(&f.db.conn)
                .await
                .unwrap()
                .is_none(),
            "legacy CACAO starts with no delegation_mode row"
        );

        // 1. Read path BEFORE backfill: resolves Attenuable and can parent a
        // redelegation + invoke.
        let graph_before = crate::auth_graph::AuthGraphSnapshot::load_with_encryption(
            &f.db.conn,
            &[cacao_hash],
            encryption.as_ref(),
        )
        .await
        .unwrap();
        assert_eq!(
            graph_before.delegation_mode(&cacao_hash),
            Some(delegation_mode::StoredDelegationMode::Attenuable),
            "unmarked real legacy attenuable CACAO must resolve Attenuable on read path"
        );
        let (child1, child1_cid) = signed_ucan_delegation(
            &holder,
            &sub1_did,
            &[(&f.kv_res, "tinycloud.kv/get")],
            &[cacao_cid],
            false,
        );
        must_ok(f.db.delegate(child1).await);
        let inv1 = signed_invocation(&sub1, &[(&f.kv_res, "tinycloud.kv/get")], &[child1_cid]);
        must_ok(f.db.invoke::<MemoryStaging>(inv1, HashMap::new()).await);

        // 2. Boot backfill marks the legacy CACAO `attenuable` without
        // rewriting `delegation.facts`, and it continues to parent
        // redelegations.
        let stats = delegation_mode::backfill(&f.db.conn, encryption.as_ref())
            .await
            .unwrap();
        assert!(stats.completed);
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.marked_attenuable, 1);
        let row = delegation::Entity::find_by_id(cacao_hash)
            .one(&f.db.conn)
            .await
            .unwrap()
            .unwrap();
        assert!(row.facts.is_none());
        let mode_row = delegation_mode::Entity::find_by_id(cacao_hash)
            .one(&f.db.conn)
            .await
            .unwrap()
            .expect("backfill must mark legacy CACAO");
        assert_eq!(
            delegation_mode::StoredDelegationMode::from_db_str(&mode_row.mode),
            delegation_mode::StoredDelegationMode::Attenuable
        );
        let (child2, child2_cid) = signed_ucan_delegation(
            &holder,
            &sub2_did,
            &[(&f.kv_res, "tinycloud.kv/get")],
            &[cacao_cid],
            false,
        );
        must_ok(f.db.delegate(child2).await);
        let inv2 = signed_invocation(&sub2, &[(&f.kv_res, "tinycloud.kv/get")], &[child2_cid]);
        must_ok(f.db.invoke::<MemoryStaging>(inv2, HashMap::new()).await);
    }
}

/// TC-3810 (F6 + Bobbie checklist b, c, d): exercise the PostgreSQL side-table
/// `delegation_mode` backfill (`NOT EXISTS` PK anti-join + per-page
/// `EXEMPT_STATEMENT_TIMEOUT`), verify historical `delegation` rows are NEVER
/// rewritten, verify same-tx writes via `SpaceDatabase::delegate`, verify
/// `ON DELETE CASCADE` removes `delegation_mode` rows when `delegation` rows
/// are deleted, and verify a second boot scans 0 rows. Runs in
/// `.github/workflows/rust.yml` (`test (workspace, PostgreSQL-backed, unit)`).
#[tokio::test]
async fn postgres_cacao_delegation_mode_boot_reindex() {
    let Some(pg) =
        crate::test_support::PostgresTestSchema::new("postgres_cacao_delegation_mode_boot_reindex")
            .await
    else {
        return;
    };

    let wallet = Wallet::from_seed(0x91);
    let space: SpaceId = format!(
        "tinycloud:{}:default",
        wallet.did.strip_prefix("did:").unwrap()
    )
    .parse()
    .unwrap();
    space::ActiveModel {
        id: Set(SpaceIdWrap(space.clone())),
    }
    .insert(&pg.conn)
    .await
    .unwrap();
    let kv_res = space
        .to_resource(
            "kv".parse().unwrap(),
            Some("secrets/pg".parse().unwrap()),
            None,
            None,
        )
        .to_string();

    let k_term = JWK::generate_ed25519().unwrap();
    let (d_term, _) = verification_method(&k_term);
    let k_bad = JWK::generate_ed25519().unwrap();
    let (d_bad, _) = verification_method(&k_bad);
    let k_ok = JWK::generate_ed25519().unwrap();
    let (d_ok, _) = verification_method(&k_ok);
    let k_ucan = JWK::generate_ed25519().unwrap();
    let (d_ucan, _) = verification_method(&k_ucan);

    let (t_token, t_cid, _) = signed_cacao_token(
        &wallet,
        &d_term,
        &[(&kv_res, "tinycloud.kv/get")],
        &[],
        Some(DelegationModeFact::Terminal),
        "pgreidxterm",
    );
    let (_, t_bytes) = TinyCloudDelegation::decode(&t_token).unwrap();
    insert_pre_upgrade_row_on(
        &pg.conn,
        Hash::from(t_cid),
        &wallet.did,
        &d_term,
        &t_bytes,
        &[(&kv_res, "tinycloud.kv/get")],
        &[],
        None,
    )
    .await;

    let (bad_bytes, bad_hash, _) = signed_cacao_with_raw_recap_tail(
        &wallet,
        &d_bad,
        &[(&kv_res, "tinycloud.kv/get")],
        r#""xyz.tinycloud.policy/delegationMode":"bogus""#,
        "pgreidxbad1",
    );
    insert_pre_upgrade_row_on(
        &pg.conn,
        bad_hash,
        &wallet.did,
        &d_bad,
        &bad_bytes,
        &[(&kv_res, "tinycloud.kv/get")],
        &[],
        None,
    )
    .await;

    let (ok_token, ok_cid, _) = signed_cacao_token(
        &wallet,
        &d_ok,
        &[(&kv_res, "tinycloud.kv/get")],
        &[],
        None,
        "pgreidxok01",
    );
    let (_, ok_bytes) = TinyCloudDelegation::decode(&ok_token).unwrap();
    insert_pre_upgrade_row_on(
        &pg.conn,
        Hash::from(ok_cid),
        &wallet.did,
        &d_ok,
        &ok_bytes,
        &[(&kv_res, "tinycloud.kv/get")],
        &[],
        None,
    )
    .await;

    let (ucan_child, _) = signed_ucan_delegation(
        &k_ok,
        &d_ucan,
        &[(&kv_res, "tinycloud.kv/get")],
        &[ok_cid],
        false,
    );
    insert_pre_upgrade_row_on(
        &pg.conn,
        ucan_child.content_hash(),
        &d_ok,
        &d_ucan,
        ucan_child.serialized_bytes(),
        &[(&kv_res, "tinycloud.kv/get")],
        &[Hash::from(ok_cid)],
        None,
    )
    .await;

    // Before backfill on Postgres: `ok_cid` is a real legacy signed DAG-CBOR
    // CACAO with NO `delegation_mode` row. On the read path it resolves
    // Attenuable and can parent a redelegation (before boot backfill runs).
    assert!(delegation_mode::Entity::find_by_id(Hash::from(ok_cid))
        .one(&pg.conn)
        .await
        .unwrap()
        .is_none());
    let unmarked_pg_graph =
        crate::auth_graph::AuthGraphSnapshot::load(&pg.conn, &[Hash::from(ok_cid)])
            .await
            .unwrap();
    assert_eq!(
        unmarked_pg_graph.delegation_mode(&Hash::from(ok_cid)),
        Some(delegation_mode::StoredDelegationMode::Attenuable),
        "unmarked real legacy attenuable CACAO must resolve Attenuable on Postgres read path"
    );
    let k_pre = JWK::generate_ed25519().unwrap();
    let (d_pre, _) = verification_method(&k_pre);
    let (pre_child, _) = signed_ucan_delegation(
        &k_ok,
        &d_pre,
        &[(&kv_res, "tinycloud.kv/get")],
        &[ok_cid],
        false,
    );
    delegation::precheck_standing_with_encryption(&pg.conn, &pre_child, false, false, None, None)
        .await
        .expect(
            "unmarked real legacy attenuable CACAO must allow redelegation on Postgres read path",
        );

    // First boot backfill against Postgres.
    let first = delegation_mode::backfill(&pg.conn, None).await.unwrap();
    assert!(first.completed);
    assert_eq!(first.scanned, 4);
    assert_eq!(first.reindexed_terminal, 1);
    assert_eq!(first.marked_invalid, 1);
    assert_eq!(first.marked_attenuable, 2);

    // Historical `delegation` rows were NOT rewritten (facts remains None),
    // and `delegation_mode` carries the exact expected marks.
    for (id, expected) in [
        (
            Hash::from(t_cid),
            delegation_mode::StoredDelegationMode::Terminal,
        ),
        (bad_hash, delegation_mode::StoredDelegationMode::Invalid),
        (
            Hash::from(ok_cid),
            delegation_mode::StoredDelegationMode::Attenuable,
        ),
        (
            ucan_child.content_hash(),
            delegation_mode::StoredDelegationMode::Attenuable,
        ),
    ] {
        let row = delegation::Entity::find_by_id(id)
            .one(&pg.conn)
            .await
            .unwrap()
            .unwrap();
        assert!(
            row.facts.is_none(),
            "Postgres backfill must never rewrite delegation.facts"
        );
        let mode_row = delegation_mode::Entity::find_by_id(id)
            .one(&pg.conn)
            .await
            .unwrap()
            .expect("backfilled delegation_mode row must exist");
        assert_eq!(
            delegation_mode::StoredDelegationMode::from_db_str(&mode_row.mode),
            expected
        );
    }

    // Second boot backfill via SpaceDatabase::new + direct check must scan 0 rows.
    let db = SpaceDatabase::new(
        pg.conn.clone(),
        MemoryStore::default(),
        StaticSecret::new(vec![0x55; 32]).unwrap(),
    )
    .await
    .unwrap();
    let second = delegation_mode::backfill(&db.conn, None).await.unwrap();
    assert!(second.completed);
    assert_eq!(second.scanned, 0, "second Postgres boot must scan 0 rows");
    assert_eq!(second.reindexed_terminal, 0);
    assert_eq!(second.marked_attenuable, 0);
    assert_eq!(second.marked_invalid, 0);

    // After backfill on Postgres: the legacy attenuable CACAO (`ok_cid`) can
    // parent a new child redelegation through `SpaceDatabase::delegate`.
    let k_post = JWK::generate_ed25519().unwrap();
    let (d_post, _) = verification_method(&k_post);
    let (post_child, _) = signed_ucan_delegation(
        &k_ok,
        &d_post,
        &[(&kv_res, "tinycloud.kv/get")],
        &[ok_cid],
        false,
    );
    must_ok(db.delegate(post_child).await);

    // Same-transaction write on Postgres multi-CTE delegate() path: writes both
    // `delegation` and `delegation_mode` atomically so backfill scans 0 rows.
    let k_new = JWK::generate_ed25519().unwrap();
    let (d_new, _) = verification_method(&k_new);
    let (new_tok, new_cid, _) = signed_cacao_token(
        &wallet,
        &d_new,
        &[(&kv_res, "tinycloud.kv/get")],
        &[],
        Some(DelegationModeFact::Terminal),
        "pgsametx001",
    );
    must_ok(db.delegate(parse_delegation(&new_tok)).await);
    let new_mode = delegation_mode::Entity::find_by_id(Hash::from(new_cid))
        .one(&pg.conn)
        .await
        .unwrap()
        .expect("Postgres delegate() must write delegation_mode in the same tx");
    assert_eq!(
        delegation_mode::StoredDelegationMode::from_db_str(&new_mode.mode),
        delegation_mode::StoredDelegationMode::Terminal
    );
    assert_eq!(
        delegation_mode::backfill(&pg.conn, None)
            .await
            .unwrap()
            .scanned,
        0
    );

    // ON DELETE CASCADE on Postgres: removing the RESTRICT-FK children
    // (`ability`, `delegation_cid_alias`) and deleting the `delegation` row
    // automatically cascades and removes its `delegation_mode` row.
    let new_hash = Hash::from(new_cid);
    abilities::Entity::delete_many()
        .filter(abilities::Column::Delegation.eq(new_hash))
        .exec(&pg.conn)
        .await
        .unwrap();
    delegation_cid_alias::Entity::delete_by_id(new_hash)
        .exec(&pg.conn)
        .await
        .unwrap();
    delegation::Entity::delete_by_id(new_hash)
        .exec(&pg.conn)
        .await
        .unwrap();
    assert!(
        delegation_mode::Entity::find_by_id(new_hash)
            .one(&pg.conn)
            .await
            .unwrap()
            .is_none(),
        "ON DELETE CASCADE must remove delegation_mode row when delegation is deleted"
    );
}
