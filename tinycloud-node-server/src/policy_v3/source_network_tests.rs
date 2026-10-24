//! TC-1423: every encryption network a Policy/v3 names must be the
//! content owner's, and active on this node, when the policy is registered.
//!
//! Registration-only fixtures over the real routes: `/delegate` imports the
//! registrant's grants (UCAN from a did:key owner, SIWE CACAO from a did:pkh
//! owner), `POST /encryption/networks` creates the Share-shaped network, and
//! `POST /policy/v3/policies` registers. Every refused case is otherwise
//! registrable: the registrant holds every root capability, so the refusal
//! comes from the source-network check alone.

use super::*;
use k256::ecdsa::SigningKey;
use rocket::{http::ContentType, local::asynchronous::Client};
use serde_json::json;
use sha3::Keccak256;
use std::future::Future;
use tinycloud_auth::{
    authorization::HeaderEncode,
    cacaos::{
        siwe::{encode_eip55, Message, Version},
        siwe_cacao::{Header as SiweHeader, Signature as SiweSignature, SiweCacao},
    },
    siwe_recap::{Ability as RecapAbility, Capability as RecapCapability},
    ssi::{claims::jwt::NumericDate, ucan::Payload},
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    encryption_network::{
        canonical::canonical_hash, CreateNetworkRequest, EncryptionService, NetworkId, Threshold,
        NETWORK_ADMIN_TYPE, NETWORK_CREATE_ACTION,
    },
    models::encryption_network,
    sea_orm::Database,
};

const KV_PATH: &str = "shares/tc-1423-n1b/document.txt";
const DECRYPT: &str = "tinycloud.encryption/decrypt";

type Ed25519Keypair = tinycloud_core::libp2p::identity::ed25519::Keypair;

/// A did:key principal: the policy owner (a session key, as in Share and the
/// CLI) or a did:key content owner.
struct KeyPrincipal {
    key: Ed25519Keypair,
    did: String,
    vm: String,
    jwk: JWK,
}

impl KeyPrincipal {
    fn generate() -> Self {
        let key = Ed25519Keypair::generate();
        let did = tinycloud_core::keys::public_key_to_did_key(
            tinycloud_core::libp2p::identity::Keypair::from(key.clone()).public(),
        );
        let mut jwk = JWK::from(Params::OKP(OctetParams {
            curve: "Ed25519".to_owned(),
            public_key: Base64urlUInt(key.public().to_bytes().to_vec()),
            private_key: Some(Base64urlUInt(key.secret().as_ref().to_vec())),
        }));
        jwk.algorithm = Some(Algorithm::EdDSA);
        let vm = format!("{did}#{}", did.trim_start_matches("did:key:"));
        Self { key, did, vm, jwk }
    }
}

/// An Ethereum account: a did:pkh content owner, as in Share.
struct PkhPrincipal {
    key: SigningKey,
    address: [u8; 20],
}

impl PkhPrincipal {
    /// A random account whose EIP-55 spelling has upper-case letters, so the
    /// case-insensitivity cases mean something.
    fn generate() -> Self {
        loop {
            let key = SigningKey::random(&mut rand::rngs::OsRng);
            let public = key.verifying_key().to_encoded_point(false);
            let digest = Keccak256::digest(&public.as_bytes()[1..]);
            let mut address = [0_u8; 20];
            address.copy_from_slice(&digest[12..]);
            let principal = Self { key, address };
            if principal.did(1) != principal.lowercase_did(1) {
                return principal;
            }
        }
    }

    /// The EIP-55 spelling space ids and session DIDs carry.
    fn did(&self, chain_id: u64) -> String {
        format!(
            "did:pkh:eip155:{chain_id}:0x{}",
            encode_eip55(&self.address)
        )
    }

    /// The spelling Share puts in its network URN (`ownerEncryptionNetwork`).
    fn lowercase_did(&self, chain_id: u64) -> String {
        format!("did:pkh:eip155:{chain_id}:0x{}", hex::encode(self.address))
    }
}

fn network(owner_did: &str, name: &str) -> String {
    format!("urn:tinycloud:encryption:{owner_did}:{name}")
}

fn kv_resource(owner_did: &str) -> anyhow::Result<ResourceId> {
    Ok(
        SpaceId::new(owner_did.parse::<DIDBuf>()?, "applications".parse()?).to_resource(
            "kv".parse()?,
            Some(KV_PATH.parse()?),
            None,
            None,
        ),
    )
}

/// The create-network body for a network `<owner_did>:share`.
fn own_network_body(owner_did: &str) -> Value {
    json!({"name": "share", "ownerDid": owner_did, "threshold": {"n": 1, "t": 1}})
}

/// The registrant's grants on the content: kv get + metadata on the content
/// resource, and decrypt on each listed network.
fn content_grants(kv: &ResourceId, decrypt: &[&str]) -> Vec<(String, &'static str)> {
    let mut grants = vec![
        (kv.as_uri().to_string(), "tinycloud.kv/get"),
        (kv.as_uri().to_string(), "tinycloud.kv/metadata"),
    ];
    grants.extend(decrypt.iter().map(|network| (network.to_string(), DECRYPT)));
    grants
}

fn refused_total(reason: &str) -> u64 {
    crate::prometheus::POLICY_SOURCE_NETWORK_REFUSED
        .with_label_values(&[reason])
        .get()
}

struct Harness {
    client: Client,
    node_did: String,
    enforcer: KeyPrincipal,
    credential_requirement: Value,
}

impl Harness {
    async fn new() -> anyhow::Result<Self> {
        Self::on(Database::connect("sqlite::memory:").await?).await
    }

    /// A fresh schema on the PostgreSQL server at `url`.
    async fn postgres(url: &str) -> anyhow::Result<Self> {
        let schema = format!("tc1423_n1b_{}", uuid::Uuid::new_v4().simple());
        Database::connect(url)
            .await?
            .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
            .await?;
        let mut url = reqwest::Url::parse(url)?;
        url.query_pairs_mut()
            .append_pair("options", &format!("-c search_path={schema}"));
        Self::on(Database::connect(url.as_str()).await?).await
    }

    async fn on(db: tinycloud_core::sea_orm::DatabaseConnection) -> anyhow::Result<Self> {
        use tinycloud_core::{
            database_artifacts::SeaOrmDatabaseArtifactRepository,
            encryption::ColumnEncryption,
            encryption_network::LocalOneOfOneBackend,
            sql::SqlService,
            storage::{either::Either, StorageConfig as _},
        };
        let vector: Value = serde_json::from_str(include_str!(
            "../../test-fixtures/tc-470-policy-credential-requirement.json"
        ))?;
        let node_secret =
            StaticSecret::new(vec![29; 32]).map_err(|_| anyhow::anyhow!("invalid secret"))?;
        let node_did = node_secret.node_did();
        let runtime = PolicyV3Runtime::new(db.clone(), node_did.clone(), node_secret);
        let storage_dir = tempfile::TempDir::new()?;
        let storage = crate::storage::file_system::FileSystemConfig::new(storage_dir.path())
            .open()
            .await?;
        let _storage_dir = storage_dir.keep();
        let tinycloud = crate::TinyCloud::new(
            db.clone().into(),
            Either::B(storage),
            StaticSecret::new(vec![0; 32]).map_err(|_| anyhow::anyhow!("invalid secret"))?,
        )
        .await?;
        let sql_dir = tempfile::TempDir::new()?;
        let sql_service = SqlService::new(
            sql_dir.path().to_string_lossy().to_string(),
            u64::MAX,
            Arc::new(SeaOrmDatabaseArtifactRepository::new(db.clone())),
        );
        let _sql_dir = sql_dir.keep();
        let encryption = EncryptionService::new_with_node_keypair(
            db.clone(),
            runtime.signer.node_keypair(),
            Arc::new(LocalOneOfOneBackend::new(ColumnEncryption::new(
                runtime
                    .signer
                    .derive_key(b"tinycloud/encryption/network-seal"),
            ))),
        );
        assert_eq!(encryption.node_did(), node_did);
        let rocket = rocket::build()
            .mount(
                "/",
                rocket::routes![
                    register_policy,
                    issue_enforcer_binding,
                    crate::routes::delegate,
                    crate::routes::encryption::create_network,
                ],
            )
            .attach(crate::tracing::TracingFairing::for_test(
                &crate::config::Config::default().log.tracing,
            ))
            .manage(tinycloud)
            .manage(runtime)
            .manage(sql_service)
            .manage(crate::config::Config::default())
            .manage(crate::quota::QuotaCache::new(None, None))
            .manage(crate::invocation_replay::InvocationReplayCache::new(
                db.clone(),
            ))
            .manage(crate::BlockStage::from(
                crate::config::StagingStorage::Memory,
            ))
            .manage(encryption);
        Ok(Self {
            client: Client::tracked(rocket).await?,
            node_did,
            enforcer: KeyPrincipal::generate(),
            credential_requirement: vector["policyProjection"].clone(),
        })
    }

    fn encryption(&self) -> &EncryptionService {
        self.client.rocket().state::<EncryptionService>().unwrap()
    }

    fn conn(&self) -> &RecoveringConnection {
        &self
            .client
            .rocket()
            .state::<PolicyV3Runtime>()
            .unwrap()
            .conn
    }

    async fn post_delegation(&self, authorization: String) -> anyhow::Result<String> {
        let response = self
            .client
            .post("/delegate")
            .header(rocket::http::Header::new("Authorization", authorization))
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        assert_eq!(status, Status::Ok, "/delegate: {body}");
        Ok(serde_json::from_str::<Value>(&body)?["cid"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing delegation cid"))?
            .to_owned())
    }

    /// A did:key issuer delegates `grants` to `audience` (a UCAN).
    async fn delegate_ucan(
        &self,
        issuer: &KeyPrincipal,
        audience: &str,
        grants: &[(String, &str)],
    ) -> anyhow::Result<String> {
        let now = OffsetDateTime::now_utc();
        let mut attenuation = Capabilities::<Value>::new();
        for (resource, ability) in grants {
            attenuation.with_action(
                resource.parse()?,
                ability.parse::<RecapAbility>()?,
                [std::collections::BTreeMap::<String, Value>::new()],
            );
        }
        let authorization = TinyCloudDelegation::Ucan(Box::new(
            Payload {
                issuer: issuer.vm.parse()?,
                audience: audience.parse()?,
                not_before: Some(NumericDate::try_from_seconds(
                    (now - Duration::seconds(5)).unix_timestamp() as f64,
                )?),
                expiration: NumericDate::try_from_seconds(
                    (now + Duration::seconds(900)).unix_timestamp() as f64,
                )?,
                nonce: Some(format!("n1b-ucan-{}", uuid::Uuid::new_v4())),
                facts: Some(vec![]),
                proof: vec![],
                attenuation,
            }
            .sign(Algorithm::EdDSA, &issuer.jwk)?,
        ))
        .encode()?;
        self.post_delegation(authorization).await
    }

    /// A did:pkh account on `chain_id` delegates `grants` to `audience` (a
    /// SIWE ReCap CACAO, as a Share session key receives).
    async fn delegate_siwe(
        &self,
        issuer: &PkhPrincipal,
        chain_id: u64,
        audience: &str,
        grants: &[(String, &str)],
    ) -> anyhow::Result<String> {
        let now = OffsetDateTime::now_utc().replace_nanosecond(0)?;
        let mut recap = RecapCapability::<Value>::new();
        for (resource, ability) in grants {
            recap.with_action(
                resource.parse()?,
                ability.parse::<RecapAbility>()?,
                [std::collections::BTreeMap::<String, Value>::new()],
            );
        }
        let message = recap.build_message(Message {
            scheme: Some("https".parse()?),
            domain: "n1b.test".parse()?,
            address: issuer.address,
            statement: None,
            uri: audience.parse()?,
            version: Version::V1,
            chain_id,
            nonce: format!("n1b{}", uuid::Uuid::new_v4().simple()),
            issued_at: (now - Duration::seconds(5)).into(),
            expiration_time: Some((now + Duration::seconds(900)).into()),
            not_before: None,
            request_id: None,
            resources: vec![],
        })?;
        let (signature, recovery_id) = issuer
            .key
            .sign_prehash_recoverable(&message.eip191_hash()?)?;
        let mut signature_bytes = [0_u8; 65];
        signature_bytes[..64].copy_from_slice(signature.to_bytes().as_ref());
        signature_bytes[64] = u8::from(recovery_id) + 27;
        let authorization = TinyCloudDelegation::Cacao(Box::new(SiweCacao::new(
            message.into(),
            SiweSignature::from(signature_bytes),
            SiweHeader,
        )))
        .encode()?;
        self.post_delegation(authorization).await
    }

    /// `POST /encryption/networks` as the SDK sends it: the session key
    /// invokes `network.create` on `invocation_network` under its CACAO, or
    /// with no proof when it names its own network (root authority by name).
    async fn create_network_via_route(
        &self,
        invoker: &KeyPrincipal,
        proof: Option<&str>,
        invocation_network: &str,
        body: Value,
    ) -> anyhow::Result<Status> {
        let now = OffsetDateTime::now_utc();
        let mut attenuation = Capabilities::<Value>::new();
        attenuation.with_action(
            invocation_network.parse()?,
            NETWORK_CREATE_ACTION.parse::<RecapAbility>()?,
            [std::collections::BTreeMap::<String, Value>::new()],
        );
        let invocation = Payload {
            issuer: invoker.vm.parse()?,
            audience: self.node_did.parse()?,
            not_before: Some(NumericDate::try_from_seconds(now.unix_timestamp() as f64)?),
            expiration: NumericDate::try_from_seconds(
                (now + Duration::seconds(30)).unix_timestamp() as f64,
            )?,
            nonce: Some(format!("n1b-create-{}", uuid::Uuid::new_v4())),
            facts: Some(vec![json!({
                "type": NETWORK_ADMIN_TYPE,
                "targetNode": self.node_did,
                "networkId": invocation_network,
                "bodyHash": canonical_hash(&body),
                "action": NETWORK_CREATE_ACTION,
            })]),
            proof: proof
                .map(str::parse)
                .into_iter()
                .collect::<Result<_, _>>()?,
            attenuation,
        }
        .sign(Algorithm::EdDSA, &invoker.jwk)?;
        let response = self
            .client
            .post("/encryption/networks")
            .header(ContentType::JSON)
            .header(rocket::http::Header::new(
                "Authorization",
                invocation.encode()?,
            ))
            .body(body.to_string())
            .dispatch()
            .await;
        let status = response.status();
        let text = response.into_string().await.unwrap_or_default();
        assert_eq!(status, Status::Ok, "create network: {text}");
        Ok(status)
    }

    async fn create_network(&self, owner_did: &str, name: &str) -> anyhow::Result<()> {
        self.encryption()
            .create_one_of_one_network(CreateNetworkRequest {
                name: name.to_owned(),
                owner_did: owner_did.to_owned(),
                threshold: Threshold::one_of_one(),
            })
            .await?;
        Ok(())
    }

    async fn set_network_state(&self, urn: &str, state: &str) -> anyhow::Result<()> {
        let updated = encryption_network::Entity::update_many()
            .col_expr(encryption_network::Column::State, Expr::value(state))
            .filter(encryption_network::Column::NetworkId.eq(urn.parse::<NetworkId>()?.to_string()))
            .exec(self.conn())
            .await?;
        assert_eq!(updated.rows_affected, 1);
        Ok(())
    }

    /// Sign and register a policy owned by `owner` over `kv_resource`,
    /// sourced from `source_network`, whose ceiling also decrypts `extra`.
    async fn register(
        &self,
        owner: &KeyPrincipal,
        kv_resource: &str,
        source_network: &str,
        extra: &[&str],
    ) -> anyhow::Result<(Status, String)> {
        self.register_full(owner, kv_resource, source_network, extra, &[])
            .await
    }

    /// [`Self::register`], with `extra_kv` as more kv ceiling entries.
    async fn register_full(
        &self,
        owner: &KeyPrincipal,
        kv_resource: &str,
        source_network: &str,
        extra: &[&str],
        extra_kv: &[&str],
    ) -> anyhow::Result<(Status, String)> {
        let now = OffsetDateTime::now_utc().replace_nanosecond(0)?;
        let issued = now - Duration::seconds(5);
        let expires = now + Duration::seconds(600);
        let mut ceiling = vec![json!({
            "kind": "kv",
            "resource": kv_resource,
            "selector": "exact",
            "actions": ["tinycloud.kv/get", "tinycloud.kv/metadata"]
        })];
        for kv in extra_kv {
            ceiling.push(json!({
                "kind": "kv",
                "resource": kv,
                "selector": "exact",
                "actions": ["tinycloud.kv/get", "tinycloud.kv/metadata"]
            }));
        }
        for network in std::iter::once(&source_network).chain(extra) {
            ceiling.push(json!({"kind": "encryption", "resource": network, "action": DECRYPT}));
        }
        let mut policy = json!({
            "schema": POLICY_V2_SCHEMA,
            "policyId": "pending",
            "ownerDid": owner.did,
            "createdAt": format_time(issued),
            "expiresAt": format_time(expires),
            "contentSource": {
                // Unique per call, so a refused policy never shares a CID
                // with one registered earlier in the same test.
                "shareId": format!("share-tc-1423-n1b-{}", uuid::Uuid::new_v4()),
                "kvResource": kv_resource,
                "selector": "exact",
                "encryptionNetwork": source_network,
                "encryptedSymmetricKeyDigestHex": "aa".repeat(32),
                "keyVersion": 1,
                "mode": "immutable",
                "initialCiphertextDigestHex": "bb".repeat(32)
            },
            "capabilityCeiling": ceiling,
            "credentialRequirement": self.credential_requirement,
            "signature": {"suite": "Ed25519", "signerDid": owner.did, "value": ""}
        });
        let mut unsigned = policy.clone();
        unsigned.as_object_mut().unwrap().remove("policyId");
        unsigned.as_object_mut().unwrap().remove("signature");
        let mut preimage = POLICY_V2_SCHEMA.as_bytes().to_vec();
        preimage.push(0);
        preimage.extend_from_slice(&canonical_json_value(&unsigned));
        policy["policyId"] = json!(format!("pol_{}", base32_lower(&Sha256::digest(&preimage))));
        policy["signature"]["value"] = json!(encode_config(
            owner.key.sign(&Sha256::digest(preimage)),
            URL_SAFE_NO_PAD
        ));
        let policy_cid = tinycloud_auth::ipld_core::cid::Cid::new_v1(
            0x55,
            tinycloud_auth::multihash_codetable::Code::Sha2_256
                .digest(&canonical_json_value(&policy)),
        )
        .to_string();
        let projections =
            registration_projections(&policy).map_err(|(_, error)| anyhow::anyhow!(error))?;
        let policy_digest =
            policy_digest_hex(&policy).map_err(|(_, error)| anyhow::anyhow!(error))?;
        let root = |audience: &str, role: &str, mode: &str, enforcer: Option<&str>| {
            let mut facts = json!({
                "ownerDid": owner.did,
                "policyId": policy["policyId"],
                "policyDigestHex": policy_digest,
                "policyCid": policy_cid,
                "contentSourceDigestHex": projections.content_source_digest_hex,
                "capabilityCeilingHashHex": projections.capability_ceiling_hash_hex,
                "nativeProjectionHashHex": projections.native_projection_hash_hex,
                "nodeAudience": self.node_did,
                "role": role,
                "mode": mode,
            });
            if let Some(enforcer) = enforcer {
                facts["enforcerDid"] = json!(enforcer);
            }
            let header = json!({
                "alg": "EdDSA",
                "jwk": {
                    "alg": "EdDSA",
                    "crv": "Ed25519",
                    "kty": "OKP",
                    "x": encode_config(owner.key.public().to_bytes(), URL_SAFE_NO_PAD),
                },
                "typ": "JWT",
                "ucv": "0.10.0",
            });
            let payload = json!({
                "att": projections.attenuation,
                "aud": audience,
                "exp": expires.unix_timestamp(),
                "fct": [facts],
                "iss": owner.vm,
                "nbf": issued.unix_timestamp(),
                "nnc": format!("tc-1423-n1b-{role}"),
                "prf": [],
            });
            let signing_input = format!(
                "{}.{}",
                encode_config(canonical_json_value(&header), URL_SAFE_NO_PAD),
                encode_config(canonical_json_value(&payload), URL_SAFE_NO_PAD)
            );
            format!(
                "{signing_input}.{}",
                encode_config(owner.key.sign(signing_input.as_bytes()), URL_SAFE_NO_PAD)
            )
        };
        let policy_root = root(
            &format!("did:tinycloud:policy:{policy_digest}"),
            "policy-authority",
            "policy-source",
            None,
        );
        let enforcement_root = root(
            &self.enforcer.did,
            "policy-enforcement",
            "conditional-mint",
            Some(&self.enforcer.did),
        );
        let binding = self
            .client
            .post("/policy/v3/enforcer-bindings")
            .header(ContentType::JSON)
            .body(
                json!({"rootExpiresAt": format_time(expires), "enforcerDid": self.enforcer.did})
                    .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(binding.status(), Status::Ok);
        let binding: Value = binding.into_json().await.unwrap();
        let response = self
            .client
            .post("/policy/v3/policies")
            .header(ContentType::JSON)
            .body(
                json!({
                    "policyCid": policy_cid,
                    "policy": policy,
                    "policyRoot": policy_root,
                    "enforcementRoot": enforcement_root,
                    "contentSourceDigestHex": projections.content_source_digest_hex,
                    "nativeProjectionHashHex": projections.native_projection_hash_hex,
                    "attestedEnforcerBinding": binding,
                })
                .to_string(),
            )
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        if status != Status::Ok {
            assert!(
                policy_v3_registration::Entity::find_by_id(policy_cid)
                    .one(self.conn())
                    .await?
                    .is_none(),
                "a refused registration must write nothing"
            );
        }
        Ok((status, body))
    }
}

/// A did:key content owner V and a session key K that V delegated kv
/// get + metadata on the content, plus decrypt on `decrypt`.
struct KeyOwnerCase {
    harness: Harness,
    owner: KeyPrincipal,
    session: KeyPrincipal,
    kv: ResourceId,
}

impl KeyOwnerCase {
    async fn new(decrypt: &[&str]) -> anyhow::Result<Self> {
        Self::on(Harness::new().await?, decrypt).await
    }

    async fn on(harness: Harness, decrypt: &[&str]) -> anyhow::Result<Self> {
        let owner = KeyPrincipal::generate();
        let session = KeyPrincipal::generate();
        let kv = kv_resource(&owner.did)?;
        let networks = decrypt
            .iter()
            .map(|name| network(&owner.did, name))
            .collect::<Vec<_>>();
        let networks = networks.iter().map(String::as_str).collect::<Vec<_>>();
        harness
            .delegate_ucan(&owner, &session.did, &content_grants(&kv, &networks))
            .await?;
        Ok(Self {
            harness,
            owner,
            session,
            kv,
        })
    }

    fn network(&self, name: &str) -> String {
        network(&self.owner.did, name)
    }

    async fn register(&self, source: &str, extra: &[&str]) -> anyhow::Result<(Status, String)> {
        self.harness
            .register(&self.session, &self.kv.to_string(), source, extra)
            .await
    }
}

async fn assert_refused(
    outcome: impl Future<Output = anyhow::Result<(Status, String)>>,
    reason: &str,
) -> anyhow::Result<()> {
    let before = refused_total(reason);
    let (status, body) = outcome.await?;
    assert_eq!(status, Status::Forbidden, "register: {body}");
    assert_eq!(body, "content-source-network-invalid");
    assert!(
        refused_total(reason) > before,
        "refusal counted under reason {reason}"
    );
    Ok(())
}

fn assert_registered((status, body): (Status, String)) {
    assert_eq!(status, Status::Ok, "register: {body}");
}

/// The content owner's own network, delegated to the session, but never
/// created: no recipient could ever decrypt through it here.
#[tokio::test]
async fn source_network_must_exist() -> anyhow::Result<()> {
    let case = KeyOwnerCase::new(&["default"]).await?;
    assert_refused(case.register(&case.network("default"), &[]), "missing").await
}

/// Decrypt requires an `active` network; registration matches it.
#[tokio::test]
async fn source_network_must_be_active() -> anyhow::Result<()> {
    let case = KeyOwnerCase::new(&["default"]).await?;
    let source = case.network("default");
    case.harness
        .create_network(&case.owner.did, "default")
        .await?;
    for state in ["pending", "rotating"] {
        case.harness.set_network_state(&source, state).await?;
        assert_refused(case.register(&source, &[]), "inactive").await?;
    }
    case.harness.set_network_state(&source, "active").await?;
    assert_registered(case.register(&source, &[]).await?);
    case.harness
        .encryption()
        .revoke_network(&source.parse()?)
        .await?;
    assert_refused(case.register(&source, &[]), "inactive").await
}

/// Every network in the ceiling is checked, not only the source: one of the
/// session's own (self-named, root by name, never created) is refused, and so
/// is a second owner network that doesn't exist.
#[tokio::test]
async fn every_policy_network_is_checked() -> anyhow::Result<()> {
    let case = KeyOwnerCase::new(&["default", "backup"]).await?;
    let source = case.network("default");
    let backup = case.network("backup");
    case.harness
        .create_network(&case.owner.did, "default")
        .await?;
    let self_named = network(&case.session.did, "share");
    assert_refused(case.register(&source, &[&self_named]), "foreign_owner").await?;
    assert_refused(case.register(&source, &[&backup]), "missing").await?;
    case.harness
        .create_network(&case.owner.did, "backup")
        .await?;
    assert_registered(case.register(&source, &[&backup]).await?);
    Ok(())
}

/// A network that exists and is active, but belongs to another principal X,
/// is refused even though the session holds X's decrypt grant on it.
#[tokio::test]
async fn existing_foreign_network_is_refused() -> anyhow::Result<()> {
    let case = KeyOwnerCase::new(&[]).await?;
    let other = KeyPrincipal::generate();
    let foreign = network(&other.did, "default");
    case.harness.create_network(&other.did, "default").await?;
    case.harness
        .delegate_ucan(&other, &case.session.did, &[(foreign.clone(), DECRYPT)])
        .await?;
    assert_refused(case.register(&foreign, &[]), "foreign_owner").await
}

/// `tinycloud://` source resources name no space owner to compare with; no
/// client emits them, so new registrations refuse them.
#[tokio::test]
async fn legacy_source_resource_is_refused() -> anyhow::Result<()> {
    let case = KeyOwnerCase::new(&["default"]).await?;
    let source = case.network("default");
    case.harness
        .create_network(&case.owner.did, "default")
        .await?;
    assert_refused(
        case.harness.register(
            &case.session,
            &format!("tinycloud://applications/kv/{KV_PATH}"),
            &source,
            &[],
        ),
        "legacy_resource",
    )
    .await
}

/// A network id whose owner isn't a valid principal can't be compared.
#[tokio::test]
async fn unparsable_network_is_refused() -> anyhow::Result<()> {
    let case = KeyOwnerCase::new(&["default"]).await?;
    let source = case.network("default");
    case.harness
        .create_network(&case.owner.did, "default")
        .await?;
    assert_refused(
        case.register(
            &source,
            &["urn:tinycloud:encryption:did:pkh:eip155:1:0xnotanaddress:default"],
        ),
        "unparsable",
    )
    .await
}

/// A did:pkh content owner and its Share-style session key: one CACAO grants
/// kv get + metadata, decrypt and network.create, with the network named in
/// Share's lower-case spelling. The session creates the network through the
/// real route, as the SDK does at sign-in (checksummed invocation resource).
async fn pkh_owner_registers(harness: Harness, name: &str) -> anyhow::Result<()> {
    let account = PkhPrincipal::generate();
    let session = KeyPrincipal::generate();
    let kv = kv_resource(&account.did(1))?;
    assert_eq!(kv.space().did().as_str(), account.did(1));
    let lowercase = network(&account.lowercase_did(1), name);
    let mut grants = content_grants(&kv, &[&lowercase]);
    grants.push((lowercase.clone(), NETWORK_CREATE_ACTION));
    let cacao = harness
        .delegate_siwe(&account, 1, &session.did, &grants)
        .await?;
    harness
        .create_network_via_route(
            &session,
            Some(&cacao),
            &network(&account.did(1), name),
            json!({"name": name, "ownerDid": account.did(1), "threshold": {"n": 1, "t": 1}}),
        )
        .await?;
    assert_registered(
        harness
            .register(&session, &kv.to_string(), &lowercase, &[])
            .await?,
    );
    Ok(())
}

/// Released Share: `<did:pkh lowercased>:default` against a checksummed space.
#[tokio::test]
async fn share_shape_registers() -> anyhow::Result<()> {
    pkh_owner_registers(Harness::new().await?, "default").await
}

/// D3: the owner's dedicated `:share` network.
#[tokio::test]
async fn share_network_of_pkh_owner_registers() -> anyhow::Result<()> {
    pkh_owner_registers(Harness::new().await?, "share").await
}

/// Same account, other chain: a different principal, so a different owner.
#[tokio::test]
async fn chain_id_mismatch_is_refused() -> anyhow::Result<()> {
    let harness = Harness::new().await?;
    let account = PkhPrincipal::generate();
    let session = KeyPrincipal::generate();
    let kv = kv_resource(&account.did(1))?;
    let other_chain = network(&account.lowercase_did(137), "default");
    harness
        .delegate_siwe(&account, 1, &session.did, &content_grants(&kv, &[]))
        .await?;
    harness
        .delegate_siwe(
            &account,
            137,
            &session.did,
            &[(other_chain.clone(), DECRYPT)],
        )
        .await?;
    harness.create_network(&account.did(137), "default").await?;
    assert_refused(
        harness.register(&session, &kv.to_string(), &other_chain, &[]),
        "foreign_owner",
    )
    .await
}

/// A policy owner K that holds only kv on V's content creates a network named
/// after itself and registers a policy whose source is K's own space on that
/// network, with a second kv ceiling entry on V's content. Every kv entry must
/// name a space of the source's owner, so registration is refused.
#[tokio::test]
async fn kv_entry_outside_the_content_owner_is_refused() -> anyhow::Result<()> {
    let case = KeyOwnerCase::new(&[]).await?;
    let k = &case.session;
    let own_network = network(&k.did, "share");
    case.harness
        .create_network_via_route(k, None, &own_network, own_network_body(&k.did))
        .await?;
    let own_source = kv_resource(&k.did)?.to_string();
    assert_refused(
        case.harness
            .register_full(k, &own_source, &own_network, &[], &[&case.kv.to_string()]),
        "foreign_space",
    )
    .await
}

/// K sharing its own space on its own network is unaffected.
#[tokio::test]
async fn own_space_on_own_network_registers() -> anyhow::Result<()> {
    let case = KeyOwnerCase::new(&[]).await?;
    let k = &case.session;
    let own_network = network(&k.did, "share");
    case.harness
        .create_network_via_route(k, None, &own_network, own_network_body(&k.did))
        .await?;
    assert_registered(
        case.harness
            .register(k, &kv_resource(&k.did)?.to_string(), &own_network, &[])
            .await?,
    );
    Ok(())
}

/// Several kv entries pass when every one names a space of the content
/// owner, here a second space of V's.
#[tokio::test]
async fn kv_entries_all_owned_by_the_content_owner_register() -> anyhow::Result<()> {
    let case = KeyOwnerCase::new(&["default"]).await?;
    case.harness
        .create_network(&case.owner.did, "default")
        .await?;
    let notes = SpaceId::new(case.owner.did.parse::<DIDBuf>()?, "notes".parse()?).to_resource(
        "kv".parse()?,
        Some(KV_PATH.parse()?),
        None,
        None,
    );
    case.harness
        .delegate_ucan(&case.owner, &case.session.did, &content_grants(&notes, &[]))
        .await?;
    assert_registered(
        case.harness
            .register_full(
                &case.session,
                &case.kv.to_string(),
                &case.network("default"),
                &[],
                &[&notes.to_string()],
            )
            .await?,
    );
    Ok(())
}

/// A legacy `tinycloud://` kv entry names no space owner: refused like a
/// legacy source.
#[tokio::test]
async fn legacy_kv_entry_is_refused() -> anyhow::Result<()> {
    let case = KeyOwnerCase::new(&["default"]).await?;
    case.harness
        .create_network(&case.owner.did, "default")
        .await?;
    let legacy = format!("tinycloud://applications/kv/{KV_PATH}");
    assert_refused(
        case.harness.register_full(
            &case.session,
            &case.kv.to_string(),
            &case.network("default"),
            &[],
            &[&legacy],
        ),
        "legacy_resource",
    )
    .await
}

/// Registration refuses a kv entry that doesn't parse, or a ceiling entry of
/// another kind, earlier (`400` from `registration_projections`). The pure
/// predicate, which also classifies stored rows, refuses both on its own.
#[test]
fn unparsable_or_unknown_ceiling_entry_fails_the_predicate() {
    let owner = KeyPrincipal::generate();
    let kv = kv_resource(&owner.did).unwrap().to_string();
    let source = network(&owner.did, "default");
    let policy = |extra: Value| {
        json!({
            "contentSource": {"kvResource": kv, "encryptionNetwork": source},
            "capabilityCeiling": [
                {"kind": "kv", "resource": kv},
                {"kind": "encryption", "resource": source},
                extra,
            ],
        })
    };
    assert!(
        content_owner_networks(&policy(json!({"kind": "encryption", "resource": source}))).is_ok()
    );
    for extra in [
        json!({"kind": "kv", "resource": "not-a-resource"}),
        json!({"kind": "kv"}),
        json!({"kind": "sql", "resource": kv}),
    ] {
        assert_eq!(
            content_owner_networks(&policy(extra.clone())).err(),
            Some(SourceNetworkRefusal::Unparsable),
            "{extra}"
        );
    }
}

fn postgres_url(test: &str) -> Option<String> {
    match std::env::var("TINYCLOUD_TEST_POSTGRES_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            assert!(
                std::env::var_os("CI").is_none(),
                "{test} requires TINYCLOUD_TEST_POSTGRES_URL, which is unset in CI (TC-381)"
            );
            eprintln!("skipping {test}: TINYCLOUD_TEST_POSTGRES_URL is unset");
            None
        }
    }
}

/// The same lookups against PostgreSQL: the Share shape registers; a missing,
/// inactive or self-named source network is refused.
#[tokio::test]
async fn postgres_source_network_check() -> anyhow::Result<()> {
    let Some(url) = postgres_url("postgres_source_network_check") else {
        return Ok(());
    };
    pkh_owner_registers(Harness::postgres(&url).await?, "default").await?;
    let case = KeyOwnerCase::on(Harness::postgres(&url).await?, &["default"]).await?;
    let source = case.network("default");
    assert_refused(case.register(&source, &[]), "missing").await?;
    case.harness
        .create_network(&case.owner.did, "default")
        .await?;
    case.harness.set_network_state(&source, "rotating").await?;
    assert_refused(case.register(&source, &[]), "inactive").await?;
    case.harness.set_network_state(&source, "active").await?;
    let self_named = network(&case.session.did, "share");
    assert_refused(case.register(&self_named, &[]), "foreign_owner").await?;
    assert_registered(case.register(&source, &[]).await?);
    Ok(())
}
