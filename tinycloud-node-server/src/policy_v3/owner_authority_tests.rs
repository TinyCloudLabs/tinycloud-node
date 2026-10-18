//! TC-1423: Policy/v3 owner-authority bindings, end to end through the
//! production app on SQLite and on PostgreSQL.
//!
//! PostgreSQL runs need `TINYCLOUD_TEST_POSTGRES_URL` (each test uses its own
//! schema); they are skipped when it is unset outside CI.

use super::*;
use rocket::{
    figment::{providers::Serialized, Figment},
    http::{ContentType, Header},
    local::asynchronous::Client,
};
use serde_json::json;
use std::collections::BTreeMap;
use tinycloud_auth::{
    authorization::{make_invocation, HeaderEncode, InvocationOptions, TinyCloudRevocation},
    cacaos::{
        siwe::{encode_eip55, Message, Version},
        siwe_cacao::{
            Eip191, Header as SiweHeader, Payload as CacaoPayload, Signature as SiweSignature,
            SiweCacao,
        },
    },
    siwe_recap::{Ability as RecapAbility, Capability as RecapCapability},
    ssi::{claims::jwt::NumericDate, ucan::Payload},
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::sea_orm::{
    sea_query::{Alias, Query},
    ConnectOptions, Database, DbBackend, Statement,
};

type Cid = tinycloud_auth::ipld_core::cid::Cid;

const CONTENT: &[u8] = b"tc-1423-content";
const KV_GET: &str = "tinycloud.kv/get";
const KV_METADATA: &str = "tinycloud.kv/metadata";
const DECRYPT: &str = "tinycloud.encryption/decrypt";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Backend {
    Sqlite,
    Postgres,
}

/// Run an async test body once per backend.
macro_rules! on_both_backends {
    ($(#[$meta:meta])* $name:ident) => {
        mod $name {
            use super::*;
            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn sqlite() -> anyhow::Result<()> {
                super::$name(Backend::Sqlite).await
            }
            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn postgres() -> anyhow::Result<()> {
                super::$name(Backend::Postgres).await
            }
        }
    };
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

fn unique(label: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "{label}{}x{}x{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos() % 1_000_000_000_000,
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

/// A database the production app can be booted on, more than once.
pub(super) struct TestDatabase {
    pub backend: Backend,
    url: String,
    _dir: tempfile::TempDir,
}

impl TestDatabase {
    pub async fn new(backend: Backend, test: &str) -> anyhow::Result<Option<Self>> {
        let dir = tempfile::tempdir()?;
        let url = match backend {
            Backend::Sqlite => format!("sqlite://{}/node.db?mode=rwc", dir.path().display()),
            Backend::Postgres => {
                let Some(url) = postgres_url(test) else {
                    return Ok(None);
                };
                let schema = unique("tc1423_");
                let admin = Database::connect(ConnectOptions::new(url.clone())).await?;
                admin
                    .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
                    .await?;
                let mut parsed = reqwest::Url::parse(&url)?;
                parsed
                    .query_pairs_mut()
                    .append_pair("options", &format!("-c search_path={schema}"));
                parsed.to_string()
            }
        };
        Ok(Some(Self {
            backend,
            url,
            _dir: dir,
        }))
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn datadir(&self) -> &std::path::Path {
        self._dir.path()
    }
}

/// A principal that signs delegations, invocations and revocations.
#[allow(clippy::large_enum_variant)]
pub(super) enum Signer {
    Key {
        keypair: tinycloud_core::libp2p::identity::ed25519::Keypair,
        jwk: JWK,
        did: String,
        vm: String,
    },
    Pkh {
        key: k256::ecdsa::SigningKey,
        address: [u8; 20],
        did: String,
    },
}

#[derive(Clone, Copy)]
pub(super) struct Window {
    pub not_before: OffsetDateTime,
    pub expiry: OffsetDateTime,
    /// The CACAO issue time; UCANs carry none.
    pub issued_at: Option<OffsetDateTime>,
}

impl Window {
    pub fn until(expiry: OffsetDateTime) -> Self {
        Self {
            not_before: now() - Duration::seconds(30),
            expiry,
            issued_at: None,
        }
    }

    pub fn issued(mut self, issued_at: OffsetDateTime) -> Self {
        self.issued_at = Some(issued_at);
        self
    }
}

pub(super) fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc().replace_nanosecond(0).unwrap()
}

fn seconds(value: OffsetDateTime) -> anyhow::Result<NumericDate> {
    Ok(NumericDate::try_from_seconds(value.unix_timestamp() as f64)?)
}

fn capabilities(grants: &[(String, &str)]) -> anyhow::Result<Capabilities<Value>> {
    let mut capabilities = Capabilities::<Value>::new();
    for (resource, ability) in grants {
        capabilities.with_action(
            resource.parse()?,
            ability.parse::<RecapAbility>()?,
            [BTreeMap::<String, Value>::new()],
        );
    }
    Ok(capabilities)
}

impl Signer {
    pub fn key() -> Self {
        let keypair = tinycloud_core::libp2p::identity::ed25519::Keypair::generate();
        let did = tinycloud_core::keys::public_key_to_did_key(
            tinycloud_core::libp2p::identity::Keypair::from(keypair.clone()).public(),
        );
        let mut jwk = JWK::from(Params::OKP(OctetParams {
            curve: "Ed25519".to_owned(),
            public_key: Base64urlUInt(keypair.public().to_bytes().to_vec()),
            private_key: Some(Base64urlUInt(keypair.secret().as_ref().to_vec())),
        }));
        jwk.algorithm = Some(Algorithm::EdDSA);
        let vm = format!("{did}#{}", did.trim_start_matches("did:key:"));
        Self::Key {
            keypair,
            jwk,
            did,
            vm,
        }
    }

    pub fn pkh() -> Self {
        use sha3::Keccak256;
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let key = k256::ecdsa::SigningKey::from_bytes(&secret.into()).expect("k256 key");
        let public = key.verifying_key().to_encoded_point(false);
        let digest = Keccak256::digest(&public.as_bytes()[1..]);
        let address: [u8; 20] = digest[12..].try_into().unwrap();
        let did = format!("did:pkh:eip155:1:0x{}", encode_eip55(&address));
        Self::Pkh { key, address, did }
    }

    pub fn did(&self) -> &str {
        match self {
            Self::Key { did, .. } | Self::Pkh { did, .. } => did,
        }
    }

    fn keypair(&self) -> &tinycloud_core::libp2p::identity::ed25519::Keypair {
        match self {
            Self::Key { keypair, .. } => keypair,
            Self::Pkh { .. } => panic!("not an Ed25519 signer"),
        }
    }

    fn sign_siwe(&self, message: &Message) -> anyhow::Result<SiweSignature> {
        let Self::Pkh { key, .. } = self else {
            anyhow::bail!("not a did:pkh signer");
        };
        let (signature, recovery) = key.sign_prehash_recoverable(&message.eip191_hash()?)?;
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(signature.to_bytes().as_ref());
        bytes[64] = u8::from(recovery) + 27;
        Ok(SiweSignature::from(bytes))
    }

    fn siwe_message(
        &self,
        uri: &str,
        nonce: &str,
        issued_at: OffsetDateTime,
        not_before: Option<OffsetDateTime>,
        expiry: OffsetDateTime,
    ) -> anyhow::Result<Message> {
        let Self::Pkh { address, .. } = self else {
            anyhow::bail!("not a did:pkh signer");
        };
        Ok(Message {
            scheme: Some("https".parse()?),
            domain: "tc1423.test".parse()?,
            address: *address,
            statement: None,
            uri: uri.parse()?,
            version: Version::V1,
            chain_id: 1,
            nonce: nonce.replace(['-', '_'], ""),
            issued_at: issued_at.into(),
            expiration_time: Some(expiry.into()),
            not_before: not_before.map(Into::into),
            request_id: None,
            resources: vec![],
        })
    }

    /// An encoded delegation to `audience`.
    pub fn delegate(
        &self,
        audience: &str,
        grants: &[(String, &str)],
        window: Window,
        proofs: &[Cid],
    ) -> anyhow::Result<String> {
        let nonce = unique("tc1423delegation");
        match self {
            Self::Key { jwk, vm, .. } => Ok(TinyCloudDelegation::Ucan(Box::new(
                Payload {
                    issuer: vm.parse()?,
                    audience: audience.parse()?,
                    not_before: Some(seconds(window.not_before)?),
                    expiration: seconds(window.expiry)?,
                    nonce: Some(nonce),
                    facts: Some(vec![]),
                    proof: proofs.to_vec(),
                    attenuation: capabilities(grants)?,
                }
                .sign(Algorithm::EdDSA, jwk)?,
            ))
            .encode()?),
            Self::Pkh { .. } => {
                anyhow::ensure!(proofs.is_empty(), "SIWE fixtures carry no proofs");
                let mut recap = RecapCapability::<Value>::new();
                for (resource, ability) in grants {
                    recap.with_action(
                        resource.parse()?,
                        ability.parse::<RecapAbility>()?,
                        [BTreeMap::<String, Value>::new()],
                    );
                }
                let message = recap.build_message(self.siwe_message(
                    audience,
                    &nonce,
                    window.issued_at.unwrap_or(window.not_before),
                    Some(window.not_before),
                    window.expiry,
                )?)?;
                let signature = self.sign_siwe(&message)?;
                Ok(TinyCloudDelegation::Cacao(Box::new(SiweCacao::new(
                    message.into(),
                    signature,
                    SiweHeader,
                )))
                .encode()?)
            }
        }
    }

    /// An encoded revocation of `cid`.
    pub fn revoke(&self, cid: &str) -> anyhow::Result<String> {
        match self {
            Self::Key { jwk, vm, did, .. } => Ok(TinyCloudRevocation::Ucan(Box::new(
                Payload {
                    issuer: vm.parse()?,
                    audience: did.parse()?,
                    not_before: None,
                    expiration: seconds(now() + Duration::seconds(60))?,
                    nonce: Some(unique("tc1423revoke")),
                    facts: Some(Vec::new()),
                    proof: Vec::new(),
                    attenuation: capabilities(&[(
                        format!("urn:cid:{cid}"),
                        "tinycloud.delegation/revoke",
                    )])?,
                }
                .sign(Algorithm::EdDSA, jwk)?,
            ))
            .encode()?),
            Self::Pkh { .. } => {
                let message = self.siwe_message(
                    &format!("ucan:{cid}"),
                    &unique("tc1423revoke"),
                    now(),
                    None,
                    now() + Duration::seconds(60),
                )?;
                let signature = self.sign_siwe(&message)?;
                Ok(TinyCloudRevocation::Cacao(Box::new(
                    CacaoPayload::from(message).sign::<Eip191>(signature),
                ))
                .encode()?)
            }
        }
    }

    /// An encoded invocation of `attenuation` citing `proof`.
    pub fn invoke(&self, attenuation: Capabilities<Value>, proof: Cid) -> anyhow::Result<String> {
        let Self::Key { jwk, vm, did, .. } = self else {
            anyhow::bail!("invocations are signed by keys");
        };
        let at = now();
        Ok(Payload {
            issuer: vm.parse()?,
            audience: did.parse()?,
            not_before: Some(seconds(at)?),
            expiration: seconds(at + Duration::seconds(30))?,
            nonce: Some(unique("tc1423invoke")),
            facts: Some(Vec::<Value>::new()),
            proof: vec![proof],
            attenuation,
        }
        .sign(Algorithm::EdDSA, jwk)?
        .encode()?)
    }
}

/// The owner-binding row as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BindingRow {
    pub state: String,
    pub unknown_reason: Option<String>,
    pub registered_mode: String,
    pub authority_expires_at: Option<String>,
    pub classifier_version: i32,
}

#[derive(Debug, Clone)]
pub(super) struct Registered {
    pub policy_cid: String,
    pub policy_root_cid: String,
}

/// Which principal owns the content space, and who owns the policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Shape {
    /// A did:key space owner delegates (UCAN) to the policy owner's key.
    KeySession,
    /// A did:pkh space owner signs SIWE to the policy owner's key, as Share
    /// and the CLI do.
    PkhSession,
    /// The policy owner owns the content space.
    SpaceOwner,
}

pub(super) struct Harness {
    pub client: Client,
    pub db: TestDatabase,
    pub space_owner: Signer,
    /// The policy owner (a key: it signs the policy and its roots).
    pub owner: Signer,
    pub holder: Signer,
    pub enforcer: Signer,
    pub content_space: SpaceId,
    pub content_resource: tinycloud_auth::resource::ResourceId,
    pub network: String,
    issuer: tinycloud_core::libp2p::identity::ed25519::Keypair,
    vector: Value,
}

/// Settings for one boot of the production app.
#[derive(Clone, Default)]
pub(super) struct Boot {
    /// The `[policy_v3]` section, passed through figment.
    pub policy_v3: Option<Value>,
}

impl Harness {
    pub async fn new(backend: Backend, shape: Shape, test: &str) -> anyhow::Result<Option<Self>> {
        Self::with_boot(backend, shape, test, Boot::default()).await
    }

    pub async fn with_boot(
        backend: Backend,
        shape: Shape,
        test: &str,
        boot: Boot,
    ) -> anyhow::Result<Option<Self>> {
        let Some(db) = TestDatabase::new(backend, test).await? else {
            return Ok(None);
        };
        let vector: Value = serde_json::from_str(include_str!(
            "../../test-fixtures/tc-470-policy-credential-requirement.json"
        ))?;
        let issuer = tinycloud_core::libp2p::identity::ed25519::Keypair::generate();
        let owner = Signer::key();
        let space_owner = match shape {
            Shape::KeySession => Signer::key(),
            Shape::PkhSession => Signer::pkh(),
            // The same key: a separate value keeps the struct simple.
            Shape::SpaceOwner => match &owner {
                Signer::Key {
                    keypair,
                    jwk,
                    did,
                    vm,
                } => Signer::Key {
                    keypair: keypair.clone(),
                    jwk: jwk.clone(),
                    did: did.clone(),
                    vm: vm.clone(),
                },
                Signer::Pkh { .. } => unreachable!(),
            },
        };
        let content_space = SpaceId::new(
            space_owner.did().parse::<DIDBuf>()?,
            "applications".parse()?,
        );
        let content_resource = content_space.clone().to_resource(
            "kv".parse()?,
            Some("shares/tc-1423/document.txt".parse()?),
            None,
            None,
        );
        let network = format!("urn:tinycloud:encryption:{}:mainnet", space_owner.did());
        let client = Self::boot_app(&db, &vector, &issuer, &boot).await?;
        let harness = Self {
            client,
            db,
            space_owner,
            owner,
            holder: Signer::key(),
            enforcer: Signer::key(),
            content_space,
            content_resource,
            network,
            issuer,
            vector,
        };
        harness.seed_content().await?;
        Ok(Some(harness))
    }

    async fn boot_app(
        db: &TestDatabase,
        vector: &Value,
        issuer: &tinycloud_core::libp2p::identity::ed25519::Keypair,
        boot: &Boot,
    ) -> anyhow::Result<Client> {
        let mut config = crate::config::Config::default();
        config.storage.datadir = db.datadir().into();
        config.storage.database = Some(db.url().to_owned());
        config.keys = serde_json::from_value(json!({
            "type": "static",
            "secret": encode_config([53u8; 32], URL_SAFE_NO_PAD),
        }))?;
        config.share_email.issuer_did = vector["policyProjection"]["issuerDid"]
            .as_str()
            .unwrap()
            .to_owned();
        config.share_email.issuer_vct = "opencredentials.email/v1".to_owned();
        config.share_email.issuer_key_version = 1;
        config.share_email.issuer_kid = vector["policyProjection"]["issuerKid"]
            .as_str()
            .unwrap()
            .to_owned();
        config.share_email.issuer_public_key =
            Some(encode_config(issuer.public().to_bytes(), URL_SAFE_NO_PAD));
        let mut figment = Figment::from(rocket::Config {
            address: "127.0.0.1".parse()?,
            log_level: rocket::config::LogLevel::Off,
            ..rocket::Config::default()
        })
        .merge(Serialized::defaults(&config));
        if let Some(policy_v3) = &boot.policy_v3 {
            figment = figment.merge(Serialized::default("policy_v3", policy_v3));
        }
        let config: crate::config::Config = figment.extract()?;
        Ok(Client::tracked(crate::app_with_control(&figment, &config, None).await?).await?)
    }

    /// Boot the production app again on the same database.
    pub async fn reboot(&mut self, boot: Boot) -> anyhow::Result<()> {
        let client = Self::boot_app(&self.db, &self.vector, &self.issuer, &boot).await?;
        self.client = client;
        Ok(())
    }

    pub fn conn(&self) -> &tinycloud_core::RecoveringConnection {
        self.client
            .rocket()
            .state::<tinycloud_core::RecoveringConnection>()
            .expect("node pool")
    }

    pub fn node_did(&self) -> String {
        self.client
            .rocket()
            .state::<PolicyV3Runtime>()
            .expect("policy runtime")
            .node_did
            .clone()
    }

    /// What a policy over the content grants, and what the owner must hold.
    pub fn owner_grants(&self) -> Vec<(String, &'static str)> {
        vec![
            (self.content_resource.to_string(), KV_GET),
            (self.content_resource.to_string(), KV_METADATA),
            (self.network.clone(), DECRYPT),
        ]
    }

    pub async fn delegate(&self, authorization: String) -> (Status, String) {
        let response = self
            .client
            .post("/delegate")
            .header(Header::new("Authorization", authorization))
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    /// Import a delegation and return its CID.
    pub async fn import(&self, authorization: String) -> anyhow::Result<String> {
        let (status, body) = self.delegate(authorization).await;
        anyhow::ensure!(status == Status::Ok, "/delegate: {status} {body}");
        Ok(serde_json::from_str::<Value>(&body)?["cid"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing cid"))?
            .to_owned())
    }

    /// The space owner grants the policy owner what a policy over the
    /// content needs.
    pub async fn grant_owner(&self, window: Window) -> anyhow::Result<String> {
        self.grant_owner_with(&self.owner_grants(), window).await
    }

    pub async fn grant_owner_with(
        &self,
        grants: &[(String, &str)],
        window: Window,
    ) -> anyhow::Result<String> {
        self.import(
            self.space_owner
                .delegate(self.owner.did(), grants, window, &[])?,
        )
        .await
    }

    async fn seed_content(&self) -> anyhow::Result<()> {
        let space_resource =
            self.content_space
                .clone()
                .to_resource("space".parse()?, None, None, None);
        let grant = self
            .import(self.space_owner.delegate(
                self.holder.did(),
                &[
                    (space_resource.to_string(), "tinycloud.space/host"),
                    (self.content_resource.to_string(), "tinycloud.kv/put"),
                    (self.content_resource.to_string(), KV_GET),
                ],
                Window::until(now() + Duration::hours(2)),
                &[],
            )?)
            .await?;
        let Signer::Key { jwk, vm, .. } = &self.holder else {
            unreachable!()
        };
        let seed = make_invocation(
            [(
                self.content_resource.clone(),
                ["tinycloud.kv/put".parse::<RecapAbility>()?],
            )],
            &grant.parse()?,
            jwk,
            vm,
            (now() + Duration::seconds(45)).unix_timestamp() as f64,
            InvocationOptions {
                nonce: Some(unique("tc1423seed")),
                ..InvocationOptions::default()
            },
        )?;
        let response = self
            .client
            .post("/invoke")
            .header(Header::new("Authorization", seed.encode()?))
            .header(ContentType::Plain)
            .body(CONTENT)
            .dispatch()
            .await;
        anyhow::ensure!(
            response.status() == Status::Ok,
            "seed: {}",
            response.status()
        );
        Ok(())
    }

    fn requested(&self) -> Vec<Value> {
        vec![json!({
            "kind": "kv",
            "resource": self.content_resource.to_string(),
            "selector": "exact",
            "actions": [KV_GET],
        })]
    }

    /// Register a policy over the content whose roots span `root`, signed
    /// by the policy owner.
    pub async fn register(&self, root: Window) -> anyhow::Result<(Status, String, Registered)> {
        let owner_did = self.owner.did().to_owned();
        let projection = self.vector["policyProjection"].clone();
        let created = (now() - Duration::seconds(60)).min(root.not_before);
        let ceiling = vec![
            json!({
                "kind": "kv",
                "resource": self.content_resource.to_string(),
                "selector": "exact",
                "actions": [KV_GET, KV_METADATA],
            }),
            json!({
                "kind": "encryption",
                "resource": self.network,
                "action": DECRYPT,
            }),
        ];
        let mut policy = json!({
            "schema": POLICY_V2_SCHEMA,
            "policyId": "pending",
            "ownerDid": owner_did,
            "createdAt": format_time(created),
            "expiresAt": format_time(root.expiry),
            "contentSource": {
                "shareId": unique("share-tc-1423-"),
                "kvResource": self.content_resource.to_string(),
                "selector": "exact",
                "encryptionNetwork": self.network,
                "encryptedSymmetricKeyDigestHex": "aa".repeat(32),
                "keyVersion": 1,
                "mode": "immutable",
                "initialCiphertextDigestHex": "bb".repeat(32)
            },
            "capabilityCeiling": ceiling,
            "credentialRequirement": projection,
            "signature": {"suite": "Ed25519", "signerDid": owner_did, "value": ""}
        });
        let mut unsigned = policy.clone();
        unsigned.as_object_mut().unwrap().remove("policyId");
        unsigned.as_object_mut().unwrap().remove("signature");
        let mut preimage = POLICY_V2_SCHEMA.as_bytes().to_vec();
        preimage.push(0);
        preimage.extend_from_slice(&canonical_json_value(&unsigned));
        policy["policyId"] = json!(format!("pol_{}", base32_lower(&Sha256::digest(&preimage))));
        policy["signature"]["value"] = json!(encode_config(
            self.owner.keypair().sign(&Sha256::digest(preimage)),
            URL_SAFE_NO_PAD
        ));
        let policy_bytes = canonical_json_value(&policy);
        let policy_cid = Cid::new_v1(
            0x55,
            tinycloud_auth::multihash_codetable::Code::Sha2_256.digest(&policy_bytes),
        )
        .to_string();
        let projections =
            registration_projections(&policy).map_err(|(_, error)| anyhow::anyhow!(error))?;
        let digest = policy_digest_hex(&policy).map_err(|(_, error)| anyhow::anyhow!(error))?;
        let node_did = self.node_did();
        let common = json!({
            "ownerDid": owner_did,
            "policyId": policy["policyId"],
            "policyDigestHex": digest,
            "policyCid": policy_cid,
            "contentSourceDigestHex": projections.content_source_digest_hex,
            "capabilityCeilingHashHex": projections.capability_ceiling_hash_hex,
            "nativeProjectionHashHex": projections.native_projection_hash_hex,
            "nodeAudience": node_did,
        });
        let Signer::Key { keypair, vm, .. } = &self.owner else {
            unreachable!()
        };
        let root_authorization =
            |audience: &str, role: &str, mode: &str, enforcer: Option<&str>| {
                let mut facts = common.as_object().unwrap().clone();
                facts.insert("role".into(), json!(role));
                facts.insert("mode".into(), json!(mode));
                if let Some(enforcer) = enforcer {
                    facts.insert("enforcerDid".into(), json!(enforcer));
                }
                let header = json!({
                    "alg": "EdDSA",
                    "jwk": {
                        "alg": "EdDSA",
                        "crv": "Ed25519",
                        "kty": "OKP",
                        "x": encode_config(keypair.public().to_bytes(), URL_SAFE_NO_PAD),
                    },
                    "typ": "JWT",
                    "ucv": "0.10.0",
                });
                let payload = json!({
                    "att": projections.attenuation.clone(),
                    "aud": audience,
                    "exp": root.expiry.unix_timestamp(),
                    "fct": [Value::Object(facts)],
                    "iss": vm,
                    "nbf": root.not_before.unix_timestamp(),
                    "nnc": unique(&format!("tc-1423-{role}-")),
                    "prf": [],
                });
                let protected = encode_config(canonical_json_value(&header), URL_SAFE_NO_PAD);
                let payload = encode_config(canonical_json_value(&payload), URL_SAFE_NO_PAD);
                let signing_input = format!("{protected}.{payload}");
                format!(
                    "{signing_input}.{}",
                    encode_config(keypair.sign(signing_input.as_bytes()), URL_SAFE_NO_PAD)
                )
            };
        let policy_root = root_authorization(
            &format!("did:tinycloud:policy:{digest}"),
            "policy-authority",
            "policy-source",
            None,
        );
        let enforcement_root = root_authorization(
            self.enforcer.did(),
            "policy-enforcement",
            "conditional-mint",
            Some(self.enforcer.did()),
        );
        let policy_root_cid = decode_root(&policy_root)
            .map_err(|(_, error)| anyhow::anyhow!(error))?
            .0;
        let binding = self
            .client
            .post("/policy/v3/enforcer-bindings")
            .header(ContentType::JSON)
            .body(
                json!({"rootExpiresAt": format_time(root.expiry), "enforcerDid": self.enforcer.did()})
                    .to_string(),
            )
            .dispatch()
            .await;
        anyhow::ensure!(binding.status() == Status::Ok, "enforcer binding");
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
        Ok((
            status,
            body,
            Registered {
                policy_cid,
                policy_root_cid,
            },
        ))
    }

    /// Register and require success.
    pub async fn register_ok(&self, root: Window) -> anyhow::Result<Registered> {
        let (status, body, registered) = self.register(root).await?;
        anyhow::ensure!(status == Status::Ok, "register: {status} {body}");
        Ok(registered)
    }

    pub async fn challenge(&self, policy: &Registered) -> (Status, String) {
        let response = self
            .client
            .post("/policy/v3/challenges")
            .header(ContentType::JSON)
            .body(
                json!({
                    "policyCid": policy.policy_cid,
                    "recipientDid": self.holder.did(),
                    "requestedCapabilities": self.requested(),
                })
                .to_string(),
            )
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    /// Challenge and mint an accountless (v4) session for the holder.
    pub async fn mint(
        &self,
        policy: &Registered,
    ) -> anyhow::Result<Result<String, (Status, String)>> {
        let (status, body) = self.challenge(policy).await;
        if status != Status::Ok {
            return Ok(Err((status, body)));
        }
        let challenge: Value = serde_json::from_str(&body)?;
        let issuer_did = self.vector["policyProjection"]["issuerDid"]
            .as_str()
            .unwrap();
        let issued = now() - Duration::seconds(5);
        let expires = now() + Duration::seconds(600);
        let holder = self.holder.did();
        let disclosure = encode_config(
            canonical_json_value(&json!(["salt-tc-1423", "email", "alice@example.test"])),
            URL_SAFE_NO_PAD,
        );
        let credential_jti = unique("credential-tc-1423-");
        let payload = json!({
            "iss": issuer_did,
            "sub": holder,
            "iat": issued.unix_timestamp(),
            "nbf": issued.unix_timestamp(),
            "exp": expires.unix_timestamp(),
            "jti": credential_jti,
            "vct": "opencredentials.email/v1",
            "profile": "tinycloud.email-proof/v1",
            "profileVersion": 1,
            "descriptorDigest": self.vector["policyProjection"]["descriptorDigest"],
            "holderBinding": {"did": holder, "signingDomain": "tinycloud.credentials/holder-binding/v1"},
            "_sd_alg": "sha-256",
            "_sd": [encode_config(Sha256::digest(disclosure.as_bytes()), URL_SAFE_NO_PAD)]
        });
        let header = json!({
            "alg": "EdDSA",
            "typ": "vc+sd-jwt",
            "kid": self.vector["policyProjection"]["issuerKid"]
        });
        let signing_input = format!(
            "{}.{}",
            encode_config(canonical_json_value(&header), URL_SAFE_NO_PAD),
            encode_config(canonical_json_value(&payload), URL_SAFE_NO_PAD)
        );
        let compact = format!(
            "{signing_input}.{}~{disclosure}",
            encode_config(self.issuer.sign(signing_input.as_bytes()), URL_SAFE_NO_PAD)
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
            "issuerKid": self.vector["policyProjection"]["issuerKid"],
            "subjectDid": holder,
            "holderDid": holder,
            "claims": claims,
            "claimsDigest": canonical_digest_base64url(&claims),
            "descriptorDigest": self.vector["policyProjection"]["descriptorDigest"],
            "credentialId": credential_jti,
            "issuedAt": format_time(issued),
            "notBefore": format_time(issued),
            "expiresAt": format_time(expires),
            "status": {"method": "none", "freshnessSeconds": 300},
            "credential": compact
        });
        let mut presentation = json!({
            "schema": CREDENTIAL_PRESENTATION_V4_SCHEMA,
            "jti": unique("presentation-tc-1423-"),
            "challengeId": challenge["challengeId"],
            "nonce": challenge["nonce"],
            "policyCid": policy.policy_cid,
            "nodeAudience": self.node_did(),
            "holderDid": holder,
            "subjectDid": holder,
            "credentialDigest": encode_config(Sha256::digest(compact.as_bytes()), URL_SAFE_NO_PAD),
            "requirementDigest": self.vector["requirementDigest"],
            "descriptorDigest": self.vector["policyProjection"]["descriptorDigest"],
            "requestedCapabilities": self.requested(),
            "issuedAt": format_time(OffsetDateTime::now_utc()),
            "expiresAt": format_time(OffsetDateTime::now_utc() + Duration::seconds(45)),
            "signature": {"suite": "Ed25519", "signerDid": holder, "value": ""}
        });
        let mut unsigned = presentation.clone();
        unsigned.as_object_mut().unwrap().remove("signature");
        let mut preimage = CREDENTIAL_PRESENTATION_V4_DOMAIN.to_vec();
        preimage.extend_from_slice(&canonical_json_value(&unsigned));
        presentation["signature"]["value"] = json!(encode_config(
            self.holder.keypair().sign(&Sha256::digest(preimage)),
            URL_SAFE_NO_PAD
        ));
        let response = self
            .client
            .post("/policy/v3/delegations")
            .header(ContentType::JSON)
            .body(
                json!({
                    "policyCid": policy.policy_cid,
                    "challengeId": challenge["challengeId"],
                    "nonce": challenge["nonce"],
                    "requirement": self.vector["sdkRequirement"],
                    "credential": credential,
                    "presentation": presentation,
                    "requestedExpiresAt": format_time(now() + Duration::seconds(300)),
                })
                .to_string(),
            )
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        if status != Status::Ok {
            return Ok(Err((status, body)));
        }
        Ok(Ok(serde_json::from_str::<Value>(&body)?["authorization"]
            .as_str()
            .unwrap()
            .to_owned()))
    }

    pub async fn mint_ok(&self, policy: &Registered) -> anyhow::Result<String> {
        self.mint(policy)
            .await?
            .map_err(|(status, body)| anyhow::anyhow!("mint: {status} {body}"))
    }

    /// The holder reads the content under a minted session.
    pub async fn read(&self, session: &str) -> anyhow::Result<(Status, Vec<u8>)> {
        let s0 = decode_delegation(session).map_err(|(_, error)| anyhow::anyhow!(error))?;
        let invocation = self.holder.invoke(
            serde_json::from_value(
                attenuation_for_policy_capabilities(&self.requested())
                    .map_err(|(_, error)| anyhow::anyhow!(error))?,
            )?,
            s0.content_hash().to_cid(0x55),
        )?;
        let response = self
            .client
            .post("/invoke")
            .header(Header::new("Authorization", invocation))
            .dispatch()
            .await;
        let status = response.status();
        Ok((status, response.into_bytes().await.unwrap_or_default()))
    }

    pub async fn revoke(&self, signer: &Signer, cid: &str) -> anyhow::Result<()> {
        let response = self
            .client
            .post("/revoke")
            .header(Header::new("Authorization", signer.revoke(cid)?))
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        anyhow::ensure!(status == Status::Ok, "revoke: {status} {body}");
        Ok(())
    }

    /// `POST /policy/v3/authorized`, signed by `signer` citing `proof`.
    pub async fn list(
        &self,
        signer: &Signer,
        cid: &str,
        cursor: Option<&str>,
        proof: Option<Cid>,
    ) -> anyhow::Result<(Status, Value)> {
        let Signer::Key { jwk, vm, did, .. } = signer else {
            anyhow::bail!("listing is invoked by keys");
        };
        let at = now();
        let invocation = Payload {
            issuer: vm.parse()?,
            audience: did.parse()?,
            not_before: Some(seconds(at)?),
            expiration: seconds(at + Duration::seconds(30))?,
            nonce: Some(unique("tc1423list")),
            facts: Some(Vec::<Value>::new()),
            proof: proof.into_iter().collect(),
            attenuation: capabilities(&[(
                format!("urn:cid:{cid}"),
                "tinycloud.delegation/status",
            )])?,
        }
        .sign(Algorithm::EdDSA, jwk)?
        .encode()?;
        let response = self
            .client
            .post("/policy/v3/authorized")
            .header(ContentType::JSON)
            .header(Header::new("Authorization", invocation))
            .body(json!({"cid": cid, "cursor": cursor}).to_string())
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        Ok((status, serde_json::from_str(&body).unwrap_or(json!(body))))
    }

    fn backend(&self) -> DbBackend {
        match self.db.backend {
            Backend::Sqlite => DbBackend::Sqlite,
            Backend::Postgres => DbBackend::Postgres,
        }
    }

    pub async fn binding(&self, policy_cid: &str) -> anyhow::Result<Option<BindingRow>> {
        let query = Query::select()
            .columns([
                Alias::new("state"),
                Alias::new("unknown_reason"),
                Alias::new("registered_mode"),
                Alias::new("authority_expires_at"),
                Alias::new("classifier_version"),
            ])
            .from(Alias::new("policy_v3_owner_binding"))
            .and_where(Expr::col(Alias::new("policy_cid")).eq(policy_cid))
            .to_owned();
        let Some(row) = self.conn().query_one(self.backend().build(&query)).await? else {
            return Ok(None);
        };
        Ok(Some(BindingRow {
            state: row.try_get("", "state")?,
            unknown_reason: row.try_get("", "unknown_reason")?,
            registered_mode: row.try_get("", "registered_mode")?,
            authority_expires_at: row.try_get("", "authority_expires_at")?,
            classifier_version: row.try_get("", "classifier_version")?,
        }))
    }

    /// The recorded closure as CID strings.
    pub async fn closure(&self, policy_cid: &str) -> anyhow::Result<Vec<String>> {
        let query = Query::select()
            .column(Alias::new("delegation_id"))
            .from(Alias::new("policy_v3_owner_authority"))
            .and_where(Expr::col(Alias::new("policy_cid")).eq(policy_cid))
            .to_owned();
        let mut ids = self
            .conn()
            .query_all(self.backend().build(&query))
            .await?
            .into_iter()
            .map(|row| {
                row.try_get::<Vec<u8>>("", "delegation_id")
                    .map_err(anyhow::Error::from)
                    .and_then(|bytes| {
                        Ok(Cid::new_v1(
                            0x55,
                            tinycloud_auth::multihash_codetable::Multihash::from_bytes(&bytes)?,
                        )
                        .to_string())
                    })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        ids.sort();
        Ok(ids)
    }

    /// Forget a policy's classification, as for one registered before the
    /// binding tables existed.
    pub async fn forget_binding(&self, policy_cid: &str) -> anyhow::Result<()> {
        for table in ["policy_v3_owner_authority", "policy_v3_owner_binding"] {
            let query = Query::delete()
                .from_table(Alias::new(table))
                .and_where(Expr::col(Alias::new("policy_cid")).eq(policy_cid))
                .to_owned();
            self.conn().execute(self.backend().build(&query)).await?;
        }
        Ok(())
    }

    pub async fn execute(&self, sql: &str) -> anyhow::Result<()> {
        self.conn()
            .execute(Statement::from_string(self.backend(), sql.to_owned()))
            .await?;
        Ok(())
    }

    /// Use the policy (a challenge) and wait for its background
    /// classification.
    pub async fn classify_on_use(&self, policy: &Registered) -> anyhow::Result<BindingRow> {
        let (status, body) = self.challenge(policy).await;
        anyhow::ensure!(status == Status::Ok, "challenge: {status} {body}");
        self.wait_for_binding(&policy.policy_cid, std::time::Duration::from_secs(20))
            .await?
            .ok_or_else(|| anyhow::anyhow!("not classified"))
    }

    /// Wait until `policy_cid` is classified as `state`, or time out;
    /// returns the last row seen.
    pub async fn wait_for_state(
        &self,
        policy_cid: &str,
        state: &str,
        timeout: std::time::Duration,
    ) -> anyhow::Result<BindingRow> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let row = self.binding(policy_cid).await?;
            if row.as_ref().is_some_and(|row| row.state == state)
                || tokio::time::Instant::now() >= deadline
            {
                return row.ok_or_else(|| anyhow::anyhow!("not classified"));
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// Wait until `policy_cid` has a classification, or time out.
    pub async fn wait_for_binding(
        &self,
        policy_cid: &str,
        timeout: std::time::Duration,
    ) -> anyhow::Result<Option<BindingRow>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(row) = self.binding(policy_cid).await? {
                return Ok(Some(row));
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(None);
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
}

fn policy_window() -> Window {
    Window::until(now() + Duration::days(1))
}

fn legacy_boot() -> Boot {
    // Every registration in these tests is before this cutover, so a row
    // without a classification is classified as legacy.
    Boot {
        policy_v3: Some(json!({
            "legacy_cutover": format_time(now() + Duration::days(1)),
        })),
    }
}

// ---------------------------------------------------------------------------
// N1: registration records the owner authority it used.
// ---------------------------------------------------------------------------

async fn registration_records_the_owner_authority(backend: Backend) -> anyhow::Result<()> {
    for shape in [Shape::KeySession, Shape::PkhSession] {
        let Some(h) =
            Harness::new(backend, shape, "registration_records_the_owner_authority").await?
        else {
            return Ok(());
        };
        let authority = h
            .grant_owner(Window::until(now() + Duration::days(2)))
            .await?;
        let policy = h.register_ok(policy_window()).await?;
        let binding = h.binding(&policy.policy_cid).await?.expect("binding");
        assert_eq!(binding.state, "bound", "{shape:?}");
        assert_eq!(binding.registered_mode, "record");
        assert_eq!(binding.unknown_reason, None);
        assert!(binding.authority_expires_at.is_some());
        assert_eq!(h.closure(&policy.policy_cid).await?, vec![authority]);
    }
    Ok(())
}
on_both_backends!(registration_records_the_owner_authority);

async fn space_owner_policies_record_root_authority(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::SpaceOwner,
        "space_owner_policies_record_root_authority",
    )
    .await?
    else {
        return Ok(());
    };
    let policy = h.register_ok(policy_window()).await?;
    let binding = h.binding(&policy.policy_cid).await?.expect("binding");
    assert_eq!(binding.state, "root-authority");
    assert!(h.closure(&policy.policy_cid).await?.is_empty());
    Ok(())
}
on_both_backends!(space_owner_policies_record_root_authority);

/// A root that outlives the owner's authority is recorded as uncapped, not
/// refused.
async fn roots_outliving_their_authority_are_recorded_uncapped(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "roots_outliving_their_authority_are_recorded_uncapped",
    )
    .await?
    else {
        return Ok(());
    };
    let authority_expiry = now() + Duration::hours(1);
    h.grant_owner(Window::until(authority_expiry)).await?;
    let policy = h.register_ok(policy_window()).await?;
    let binding = h.binding(&policy.policy_cid).await?.expect("binding");
    assert_eq!(binding.state, "bound-uncapped");
    assert_eq!(
        binding.authority_expires_at.as_deref(),
        Some(format_time(authority_expiry).as_str())
    );
    Ok(())
}
on_both_backends!(roots_outliving_their_authority_are_recorded_uncapped);

/// [F1] A link holder that delegates back to the policy owner, or the owner
/// delegating to itself, never becomes the recorded authority.
async fn delegations_back_to_the_owner_are_never_recorded(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "delegations_back_to_the_owner_are_never_recorded",
    )
    .await?
    else {
        return Ok(());
    };
    // One window for the grant and everything derived from it: a child may
    // not outlive its parent, and two `now()`s can straddle a second.
    let window = Window::until(now() + Duration::days(2));
    let authority = h.grant_owner(window).await?;
    let authority_cid: Cid = authority.parse()?;
    let link_holder = Signer::key();
    let grants = h.owner_grants();
    let link = h
        .import(
            h.owner
                .delegate(link_holder.did(), &grants, window, &[authority_cid])?,
        )
        .await?;
    let back = h
        .import(link_holder.delegate(h.owner.did(), &grants, window, &[link.parse()?])?)
        .await?;
    let (self_status, self_body) = h
        .delegate(
            h.owner
                .delegate(h.owner.did(), &grants, window, &[authority_cid])?,
        )
        .await;
    let policy = h.register_ok(policy_window()).await?;
    let closure = h.closure(&policy.policy_cid).await?;
    assert_eq!(
        closure,
        vec![authority.clone()],
        "back={back} self={self_status} {self_body}"
    );
    let (status, page) = h.list(&h.space_owner, &authority, None, None).await?;
    assert_eq!(status, Status::Ok, "{page}");
    assert_eq!(page["policies"][0]["policyCid"], json!(policy.policy_cid));
    Ok(())
}
on_both_backends!(delegations_back_to_the_owner_are_never_recorded);

/// [F1] The same in the general window, where the owner's authority is
/// re-delegated (so the owner-first step finds nothing) and the loop-back
/// delegations sort ahead of it.
async fn loop_back_delegations_are_skipped_in_the_general_window(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "loop_back_delegations_are_skipped_in_the_general_window",
    )
    .await?
    else {
        return Ok(());
    };
    let grants = h.owner_grants();
    let window = Window::until(now() + Duration::days(2));
    let intermediary = Signer::key();
    let upstream = h
        .import(
            h.space_owner
                .delegate(intermediary.did(), &grants, window, &[])?,
        )
        .await?;
    let authority_encoded =
        intermediary.delegate(h.owner.did(), &grants, window, &[upstream.parse()?])?;
    let authority_id = graph_id(&authority_encoded)?;
    let authority = h.import(authority_encoded).await?;
    let link_holder = Signer::key();
    let link = h
        .import(
            h.owner
                .delegate(link_holder.did(), &grants, window, &[authority.parse()?])?,
        )
        .await?;
    // Both loop-back delegations sort before the authority in the window's
    // tie-break order (no issue time, then id), so only the filter skips them.
    let back = sorting_before(&authority_id, || {
        link_holder.delegate(h.owner.did(), &grants, window, &[link.parse()?])
    })?;
    let back = h.import(back).await?;
    let to_self = sorting_before(&authority_id, || {
        h.owner
            .delegate(h.owner.did(), &grants, window, &[authority.parse()?])
    })?;
    let (self_status, self_body) = h.delegate(to_self).await;
    let policy = h.register_ok(policy_window()).await?;
    let mut expected = vec![authority.clone(), upstream.clone()];
    expected.sort();
    assert_eq!(
        h.closure(&policy.policy_cid).await?,
        expected,
        "back={back} self={self_status} {self_body}"
    );
    let (status, page) = h.list(&h.space_owner, &upstream, None, None).await?;
    assert_eq!(status, Status::Ok, "{page}");
    assert_eq!(page["policies"][0]["policyCid"], json!(policy.policy_cid));
    Ok(())
}
on_both_backends!(loop_back_delegations_are_skipped_in_the_general_window);

/// The stored graph id of an encoded delegation.
fn graph_id(encoded: &str) -> anyhow::Result<Vec<u8>> {
    Ok(decode_delegation(encoded)
        .map_err(|(_, error)| anyhow::anyhow!(error))?
        .content_hash()
        .as_ref()
        .to_vec())
}

/// The highest-sorting of 64 freshly signed delegations, so that later ids
/// can be chosen to sort before it (each fresh one does with probability
/// about 63/64, whatever the id layout).
fn high_id(mut sign: impl FnMut() -> anyhow::Result<String>) -> anyhow::Result<String> {
    let mut best: Option<(Vec<u8>, String)> = None;
    for _ in 0..64 {
        let encoded = sign()?;
        let id = graph_id(&encoded)?;
        if best.as_ref().is_none_or(|(best_id, _)| id > *best_id) {
            best = Some((id, encoded));
        }
    }
    Ok(best.expect("64 candidates").1)
}

/// Set a registration's `registered_at`, as for one registered earlier.
async fn backdate(
    h: &Harness,
    policy_cid: &str,
    registered_at: OffsetDateTime,
) -> anyhow::Result<()> {
    let update = Query::update()
        .table(Alias::new("policy_v3_registration"))
        .value(Alias::new("registered_at"), format_time(registered_at))
        .and_where(Expr::col(Alias::new("policy_cid")).eq(policy_cid))
        .to_owned();
    h.conn().execute(h.backend().build(&update)).await?;
    Ok(())
}

/// Sign fresh delegations until one's graph id sorts before `target`.
fn sorting_before(
    target: &[u8],
    mut sign: impl FnMut() -> anyhow::Result<String>,
) -> anyhow::Result<String> {
    for _ in 0..512 {
        let encoded = sign()?;
        if graph_id(&encoded)?.as_slice() < target {
            return Ok(encoded);
        }
    }
    anyhow::bail!("no delegation sorted before the target")
}

/// [C1] Delegations to the policy owner from strangers' own spaces, with
/// future or backdated issue times, cannot push the space owner's grant out
/// of the candidate window, at registration or in the legacy backfill.
async fn stranger_delegations_cannot_starve_the_owner_grant(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::with_boot(
        backend,
        Shape::KeySession,
        "stranger_delegations_cannot_starve_the_owner_grant",
        legacy_boot(),
    )
    .await?
    else {
        return Ok(());
    };
    let authority = h
        .grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let legacy = h.register_ok(policy_window()).await?;
    h.forget_binding(&legacy.policy_cid).await?;
    // More than the general window (256 rows) on each side of the
    // registration time: future issue times lead it at registration, and
    // backdated ones lead it in the legacy backfill.
    flood(&h, 260, Duration::days(300)).await?;
    flood(&h, 260, -Duration::days(300)).await?;
    let policy = h.register_ok(policy_window()).await?;
    assert_eq!(
        h.closure(&policy.policy_cid).await?,
        vec![authority.clone()]
    );
    // First use of the legacy registration classifies it.
    let binding = h.classify_on_use(&legacy).await?;
    assert_eq!(binding.registered_mode, "backfill");
    assert_eq!(binding.state, "bound");
    assert_eq!(h.closure(&legacy.policy_cid).await?, vec![authority]);
    Ok(())
}
on_both_backends!(stranger_delegations_cannot_starve_the_owner_grant);

/// SIWE delegations from strangers' own spaces to the policy owner.
async fn flood(h: &Harness, count: usize, issued_offset: Duration) -> anyhow::Result<()> {
    for _ in 0..count {
        let stranger = Signer::pkh();
        let space = SpaceId::new(stranger.did().parse::<DIDBuf>()?, "applications".parse()?);
        let resource = space.to_resource("kv".parse()?, Some("x".parse()?), None, None);
        h.import(stranger.delegate(
            h.owner.did(),
            &[(resource.to_string(), KV_GET)],
            Window::until(now() + Duration::days(400)).issued(now() + issued_offset),
            &[],
        )?)
        .await?;
    }
    Ok(())
}

/// The general window only holds delegations touching the capability's space
/// or network, so strangers cannot crowd out a re-delegated authority that
/// the owner-first step does not see.
async fn strangers_cannot_crowd_the_general_window(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = Harness::with_boot(
        backend,
        Shape::KeySession,
        "strangers_cannot_crowd_the_general_window",
        legacy_boot(),
    )
    .await?
    else {
        return Ok(());
    };
    let intermediary = Signer::key();
    let window = Window::until(now() + Duration::days(2));
    let upstream = h
        .import(
            h.space_owner
                .delegate(intermediary.did(), &h.owner_grants(), window, &[])?,
        )
        .await?;
    let authority = h
        .import(intermediary.delegate(
            h.owner.did(),
            &h.owner_grants(),
            window,
            &[upstream.parse()?],
        )?)
        .await?;
    let legacy = h.register_ok(policy_window()).await?;
    h.forget_binding(&legacy.policy_cid).await?;
    flood(&h, 300, -Duration::days(300)).await?;
    let binding = h.classify_on_use(&legacy).await?;
    assert_eq!(binding.state, "bound");
    let mut expected = vec![authority, upstream];
    expected.sort();
    assert_eq!(h.closure(&legacy.policy_cid).await?, expected);
    Ok(())
}
on_both_backends!(strangers_cannot_crowd_the_general_window);

/// `starved` needs both steps to miss with candidates left unexamined: here
/// the general window is full of loop-back delegations (skipped without using
/// a try) ahead of the re-delegated authority. `starved` is not final.
async fn a_general_window_full_of_skipped_rows_is_starved(backend: Backend) -> anyhow::Result<()> {
    let Some(mut h) = Harness::with_boot(
        backend,
        Shape::KeySession,
        "a_general_window_full_of_skipped_rows_is_starved",
        legacy_boot(),
    )
    .await?
    else {
        return Ok(());
    };
    let grants = h.owner_grants();
    let window = Window::until(now() + Duration::days(2));
    let intermediary = Signer::key();
    let upstream = h
        .import(
            h.space_owner
                .delegate(intermediary.did(), &grants, window, &[])?,
        )
        .await?;
    let authority_encoded =
        high_id(|| intermediary.delegate(h.owner.did(), &grants, window, &[upstream.parse()?]))?;
    let authority_id = graph_id(&authority_encoded)?;
    let authority = h.import(authority_encoded).await?;
    let legacy = h.register_ok(policy_window()).await?;
    h.forget_binding(&legacy.policy_cid).await?;
    let link_holder = Signer::key();
    let link = h
        .import(
            h.owner
                .delegate(link_holder.did(), &grants, window, &[authority.parse()?])?,
        )
        .await?;
    for _ in 0..260 {
        let back = sorting_before(&authority_id, || {
            link_holder.delegate(h.owner.did(), &grants, window, &[link.parse()?])
        })?;
        h.import(back).await?;
    }
    let binding = h.classify_on_use(&legacy).await?;
    assert_eq!(binding.state, "unknown");
    assert_eq!(binding.unknown_reason.as_deref(), Some("starved"));
    // `starved` is not final: once the owner holds a grant the owner-first
    // step finds, a later use (here in a fresh process, past the back-off)
    // classifies it again.
    h.grant_owner(Window {
        not_before: now() - Duration::hours(1),
        expiry: now() + Duration::days(2),
        issued_at: None,
    })
    .await?;
    h.reboot(legacy_boot()).await?;
    h.challenge(&legacy).await;
    let binding = h
        .wait_for_state(
            &legacy.policy_cid,
            "bound",
            std::time::Duration::from_secs(20),
        )
        .await?;
    assert_eq!(binding.state, "bound", "starved was treated as final");
    Ok(())
}
on_both_backends!(a_general_window_full_of_skipped_rows_is_starved);

/// Loop-back candidates ahead of the authority in the general window don't
/// use up its tries: 40 of them (more than the 32 tries) still leave the
/// authority reachable.
async fn loop_back_rows_do_not_use_up_tries(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "loop_back_rows_do_not_use_up_tries",
    )
    .await?
    else {
        return Ok(());
    };
    let grants = h.owner_grants();
    let window = Window::until(now() + Duration::days(2));
    let intermediary = Signer::key();
    let upstream = h
        .import(
            h.space_owner
                .delegate(intermediary.did(), &grants, window, &[])?,
        )
        .await?;
    let authority_encoded =
        high_id(|| intermediary.delegate(h.owner.did(), &grants, window, &[upstream.parse()?]))?;
    let authority_id = graph_id(&authority_encoded)?;
    let authority = h.import(authority_encoded).await?;
    let link_holder = Signer::key();
    let link = h
        .import(
            h.owner
                .delegate(link_holder.did(), &grants, window, &[authority.parse()?])?,
        )
        .await?;
    for _ in 0..40 {
        let back = sorting_before(&authority_id, || {
            link_holder.delegate(h.owner.did(), &grants, window, &[link.parse()?])
        })?;
        h.import(back).await?;
    }
    let policy = h.register_ok(policy_window()).await?;
    let mut expected = vec![authority, upstream];
    expected.sort();
    assert_eq!(h.closure(&policy.policy_cid).await?, expected);
    Ok(())
}
on_both_backends!(loop_back_rows_do_not_use_up_tries);

/// Delegations to the owner from holders of the space owner's authority
/// (they pass the general window's scope) sort ahead of the space owner's
/// own grant; the owner-first step still records that grant.
async fn owner_derived_delegations_cannot_displace_the_owner_grant(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "owner_derived_delegations_cannot_displace_the_owner_grant",
    )
    .await?
    else {
        return Ok(());
    };
    let grants = h.owner_grants();
    let window = Window::until(now() + Duration::days(2));
    let authority_encoded =
        high_id(|| h.space_owner.delegate(h.owner.did(), &grants, window, &[]))?;
    let authority_id = graph_id(&authority_encoded)?;
    let authority = h.import(authority_encoded).await?;
    let holder = Signer::key();
    let upstream = h
        .import(h.space_owner.delegate(holder.did(), &grants, window, &[])?)
        .await?;
    for _ in 0..260 {
        let derived = sorting_before(&authority_id, || {
            holder.delegate(h.owner.did(), &grants, window, &[upstream.parse()?])
        })?;
        h.import(derived).await?;
    }
    let policy = h.register_ok(policy_window()).await?;
    assert_eq!(h.closure(&policy.policy_cid).await?, vec![authority]);
    Ok(())
}
on_both_backends!(owner_derived_delegations_cannot_displace_the_owner_grant);

/// The legacy classifier only considers grants issued no later than the
/// registration.
async fn the_legacy_classifier_ignores_grants_issued_after_registration(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::with_boot(
        backend,
        Shape::PkhSession,
        "the_legacy_classifier_ignores_grants_issued_after_registration",
        legacy_boot(),
    )
    .await?
    else {
        return Ok(());
    };
    // Valid since two hours ago, but issued now.
    h.grant_owner(Window {
        not_before: now() - Duration::hours(2),
        expiry: now() + Duration::days(2),
        issued_at: Some(now()),
    })
    .await?;
    let legacy = h.register_ok(policy_window()).await?;
    h.forget_binding(&legacy.policy_cid).await?;
    backdate(&h, &legacy.policy_cid, now() - Duration::hours(1)).await?;
    let binding = h.classify_on_use(&legacy).await?;
    assert_eq!(binding.state, "unknown");
    assert_eq!(binding.unknown_reason.as_deref(), Some("missing"));
    Ok(())
}
on_both_backends!(the_legacy_classifier_ignores_grants_issued_after_registration);

/// [C1] With a SIWE owner grant: strangers' delegations issued after it
/// (future at registration, or between it and a legacy registration) don't
/// displace it.
async fn stranger_delegations_cannot_starve_a_siwe_owner_grant(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = Harness::with_boot(
        backend,
        Shape::PkhSession,
        "stranger_delegations_cannot_starve_a_siwe_owner_grant",
        legacy_boot(),
    )
    .await?
    else {
        return Ok(());
    };
    let authority = h
        .grant_owner(Window {
            not_before: now() - Duration::hours(3),
            expiry: now() + Duration::days(2),
            issued_at: Some(now() - Duration::hours(2)),
        })
        .await?;
    let legacy = h.register_ok(policy_window()).await?;
    h.forget_binding(&legacy.policy_cid).await?;
    backdate(&h, &legacy.policy_cid, now() - Duration::minutes(30)).await?;
    flood(&h, 260, -Duration::hours(1)).await?;
    flood(&h, 260, Duration::days(300)).await?;
    let policy = h.register_ok(policy_window()).await?;
    assert_eq!(
        h.closure(&policy.policy_cid).await?,
        vec![authority.clone()]
    );
    let binding = h.classify_on_use(&legacy).await?;
    assert_eq!(binding.state, "bound");
    assert_eq!(h.closure(&legacy.policy_cid).await?, vec![authority]);
    Ok(())
}
on_both_backends!(stranger_delegations_cannot_starve_a_siwe_owner_grant);

/// [F9] An older grant that outlives the root is recorded over a newer one
/// that does not.
async fn a_grant_outliving_the_root_is_preferred(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::PkhSession,
        "a_grant_outliving_the_root_is_preferred",
    )
    .await?
    else {
        return Ok(());
    };
    let long = h
        .grant_owner(Window::until(now() + Duration::days(2)).issued(now() - Duration::minutes(10)))
        .await?;
    let short = h
        .grant_owner(Window::until(now() + Duration::hours(1)).issued(now() - Duration::minutes(1)))
        .await?;
    let policy = h.register_ok(policy_window()).await?;
    assert_eq!(
        h.closure(&policy.policy_cid).await?,
        vec![long],
        "short={short}"
    );
    assert_eq!(h.binding(&policy.policy_cid).await?.unwrap().state, "bound");
    Ok(())
}
on_both_backends!(a_grant_outliving_the_root_is_preferred);

// ---------------------------------------------------------------------------
// N1: legacy registrations are classified on first use, claim-first.
// ---------------------------------------------------------------------------

async fn concurrent_first_uses_store_one_classification(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = Harness::with_boot(
        backend,
        Shape::KeySession,
        "concurrent_first_uses_store_one_classification",
        legacy_boot(),
    )
    .await?
    else {
        return Ok(());
    };
    let authority = h
        .grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let policy = h.register_ok(policy_window()).await?;
    h.forget_binding(&policy.policy_cid).await?;
    let results = futures::future::join_all((0..6).map(|_| h.challenge(&policy))).await;
    for (status, body) in results {
        assert_eq!(status, Status::Ok, "{body}");
    }
    h.wait_for_binding(&policy.policy_cid, std::time::Duration::from_secs(20))
        .await?
        .expect("classified");
    let count = Query::select()
        .expr(Expr::col(Alias::new("policy_cid")).count())
        .from(Alias::new("policy_v3_owner_binding"))
        .and_where(Expr::col(Alias::new("policy_cid")).eq(policy.policy_cid.clone()))
        .to_owned();
    let row = h
        .conn()
        .query_one(h.backend().build(&count))
        .await?
        .unwrap();
    assert_eq!(row.try_get_by_index::<i64>(0)?, 1);
    assert_eq!(h.closure(&policy.policy_cid).await?, vec![authority]);
    Ok(())
}
on_both_backends!(concurrent_first_uses_store_one_classification);

/// [F3] A classification that cannot be stored is served from memory and
/// leaves the row pending.
async fn a_failed_classification_write_still_serves(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = Harness::with_boot(
        backend,
        Shape::KeySession,
        "a_failed_classification_write_still_serves",
        legacy_boot(),
    )
    .await?
    else {
        return Ok(());
    };
    h.grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let policy = h.register_ok(policy_window()).await?;
    h.forget_binding(&policy.policy_cid).await?;
    h.execute("DROP TABLE policy_v3_owner_authority").await?;
    // The challenge starts a background classification whose write fails.
    let session = h.mint_ok(&policy).await?;
    let (status, body) = h.read(&session).await?;
    assert_eq!(status, Status::Ok, "{body:?}");
    assert_eq!(body, CONTENT);
    assert_eq!(
        h.wait_for_binding(&policy.policy_cid, std::time::Duration::from_secs(2))
            .await?,
        None
    );
    Ok(())
}
on_both_backends!(a_failed_classification_write_still_serves);

/// [F8] A legacy registration whose original authority was revoked binds
/// to a live alternate; with none left it is recorded `unknown`.
async fn legacy_classification_falls_through_to_a_live_alternate(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(mut h) = Harness::with_boot(
        backend,
        Shape::KeySession,
        "legacy_classification_falls_through_to_a_live_alternate",
        legacy_boot(),
    )
    .await?
    else {
        return Ok(());
    };
    let first = h
        .grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let second = h
        .grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let policy = h.register_ok(policy_window()).await?;
    let recorded = h.closure(&policy.policy_cid).await?;
    assert_eq!(recorded.len(), 1);
    let alternate = if recorded[0] == first {
        &second
    } else {
        &first
    };
    h.revoke(&h.space_owner, &recorded[0]).await?;
    h.forget_binding(&policy.policy_cid).await?;
    h.classify_on_use(&policy).await?;
    assert_eq!(
        h.closure(&policy.policy_cid).await?,
        vec![alternate.clone()]
    );

    h.revoke(&h.space_owner, alternate).await?;
    h.forget_binding(&policy.policy_cid).await?;
    // A fresh process: this one remembers the earlier classification as
    // final.
    h.reboot(legacy_boot()).await?;
    let binding = h.classify_on_use(&policy).await?;
    assert_eq!(binding.state, "unknown");
    assert_eq!(binding.unknown_reason.as_deref(), Some("revoked"));
    assert!(h.closure(&policy.policy_cid).await?.is_empty());
    Ok(())
}
on_both_backends!(legacy_classification_falls_through_to_a_live_alternate);

/// An `unknown` row written by an older classifier is classified again.
async fn older_unknown_classifications_are_reevaluated(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = Harness::with_boot(
        backend,
        Shape::KeySession,
        "older_unknown_classifications_are_reevaluated",
        legacy_boot(),
    )
    .await?
    else {
        return Ok(());
    };
    let authority = h
        .grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let policy = h.register_ok(policy_window()).await?;
    h.forget_binding(&policy.policy_cid).await?;
    let insert = Query::insert()
        .into_table(Alias::new("policy_v3_owner_binding"))
        .columns([
            Alias::new("policy_cid"),
            Alias::new("state"),
            Alias::new("authority_expires_at"),
            Alias::new("unknown_reason"),
            Alias::new("classifier_version"),
            Alias::new("registered_mode"),
            Alias::new("created_at"),
        ])
        .values_panic([
            policy.policy_cid.clone().into(),
            "unknown".into(),
            Option::<String>::None.into(),
            "missing".into(),
            0i32.into(),
            "backfill".into(),
            format_time(now()).into(),
        ])
        .to_owned();
    h.conn().execute(h.backend().build(&insert)).await?;
    h.challenge(&policy).await;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let binding = loop {
        let binding = h.binding(&policy.policy_cid).await?.expect("row");
        if binding.classifier_version > 0 || tokio::time::Instant::now() >= deadline {
            break binding;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert_eq!(binding.state, "bound");
    assert!(binding.classifier_version >= 2);
    assert_eq!(h.closure(&policy.policy_cid).await?, vec![authority]);
    Ok(())
}
on_both_backends!(older_unknown_classifications_are_reevaluated);

/// The sweep classifies pending registrations only when enabled.
async fn the_sweep_runs_only_when_enabled(backend: Backend) -> anyhow::Result<()> {
    let Some(mut h) = Harness::with_boot(
        backend,
        Shape::KeySession,
        "the_sweep_runs_only_when_enabled",
        legacy_boot(),
    )
    .await?
    else {
        return Ok(());
    };
    h.grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let policy = h.register_ok(policy_window()).await?;
    h.forget_binding(&policy.policy_cid).await?;
    h.reboot(legacy_boot()).await?;
    assert_eq!(
        h.wait_for_binding(&policy.policy_cid, std::time::Duration::from_secs(2))
            .await?,
        None
    );
    let mut enabled = legacy_boot();
    enabled.policy_v3.as_mut().unwrap()["owner_binding_backfill"] =
        json!({"enabled": true, "policies_per_second": 50});
    h.reboot(enabled).await?;
    let binding = h
        .wait_for_binding(&policy.policy_cid, std::time::Duration::from_secs(20))
        .await?
        .expect("swept");
    assert_eq!(binding.registered_mode, "backfill");
    assert_eq!(binding.state, "bound");
    Ok(())
}
on_both_backends!(the_sweep_runs_only_when_enabled);

/// [F5][F6] Rollback: `down` drops both tables; after a re-upgrade only
/// registrations before the configured cutover are legacy.
async fn rollback_and_reupgrade_respect_the_configured_cutover(
    backend: Backend,
) -> anyhow::Result<()> {
    use tinycloud_core::sea_orm_migration::MigratorTrait;
    let Some(mut h) = Harness::new(
        backend,
        Shape::KeySession,
        "rollback_and_reupgrade_respect_the_configured_cutover",
    )
    .await?
    else {
        return Ok(());
    };
    h.grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let before = h.register_ok(policy_window()).await?;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let cutover = OffsetDateTime::now_utc();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let during = h.register_ok(policy_window()).await?;
    let direct = Database::connect(ConnectOptions::new(h.db.url().to_owned())).await?;
    tinycloud_core::migrations::Migrator::down(&direct, Some(1)).await?;
    drop(direct);
    assert!(
        h.binding(&before.policy_cid).await.is_err(),
        "tables dropped"
    );
    h.reboot(Boot {
        policy_v3: Some(json!({"legacy_cutover": format_time(cutover)})),
    })
    .await?;
    assert_eq!(
        h.classify_on_use(&before).await?.registered_mode,
        "backfill"
    );
    assert_eq!(h.classify_on_use(&during).await?.registered_mode, "record");
    Ok(())
}
on_both_backends!(rollback_and_reupgrade_respect_the_configured_cutover);

// ---------------------------------------------------------------------------
// N1: listing by any closure member.
// ---------------------------------------------------------------------------

async fn listing_is_limited_to_parties_of_the_delegation(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "listing_is_limited_to_parties_of_the_delegation",
    )
    .await?
    else {
        return Ok(());
    };
    let authority = h
        .grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let policy = h.register_ok(policy_window()).await?;
    for (label, signer) in [("space owner", &h.space_owner), ("policy owner", &h.owner)] {
        let (status, page) = h.list(signer, &authority, None, None).await?;
        assert_eq!(status, Status::Ok, "{label}: {page}");
        let listed = &page["policies"][0];
        assert_eq!(listed["policyCid"], json!(policy.policy_cid));
        assert_eq!(listed["policyRootCid"], json!(policy.policy_root_cid));
        assert_eq!(listed["rootState"], json!("active"));
        assert_eq!(listed["ownerAuthorityState"], json!("bound"));
        assert!(listed.get("policy").is_none());
        assert_eq!(page["nextCursor"], Value::Null);
    }
    let stranger = Signer::key();
    for (label, signer) in [("recipient", &h.holder), ("stranger", &stranger)] {
        let (status, page) = h.list(signer, &authority, None, None).await?;
        assert_eq!(status, Status::Forbidden, "{label}: {page}");
    }
    Ok(())
}
on_both_backends!(listing_is_limited_to_parties_of_the_delegation);

/// Keyset pages neither skip nor repeat existing rows while rows are added.
async fn listing_pages_are_stable_under_inserts(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "listing_pages_are_stable_under_inserts",
    )
    .await?
    else {
        return Ok(());
    };
    let authority = h
        .grant_owner(Window::until(now() + Duration::days(2)))
        .await?;
    let template = h.register_ok(policy_window()).await?;
    let authority_bytes = authority.parse::<Cid>()?.hash().to_bytes();
    let existing = (0..120)
        .map(|index| format!("synthetic-{:04}", index * 2 + 1))
        .collect::<Vec<_>>();
    insert_synthetic(&h, &template.policy_cid, &authority_bytes, existing.clone()).await?;
    let (status, first) = h.list(&h.space_owner, &authority, None, None).await?;
    assert_eq!(status, Status::Ok, "{first}");
    let first_page = first["policies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["policyCid"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(first_page.len(), 100);
    let cursor = first["nextCursor"].as_str().expect("cursor").to_owned();
    // Rows added on both sides of the cursor.
    insert_synthetic(
        &h,
        &template.policy_cid,
        &authority_bytes,
        vec!["synthetic-0000".into(), "synthetic-0300".into()],
    )
    .await?;
    let (status, second) = h
        .list(&h.space_owner, &authority, Some(&cursor), None)
        .await?;
    assert_eq!(status, Status::Ok, "{second}");
    let second_page = second["policies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["policyCid"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let mut all_existing = existing.clone();
    all_existing.push(template.policy_cid.clone());
    all_existing.sort();
    let mut seen = first_page.clone();
    seen.extend(
        second_page
            .iter()
            .filter(|cid| cid.as_str() != "synthetic-0300")
            .cloned(),
    );
    seen.sort();
    assert_eq!(seen, all_existing, "no existing row skipped or repeated");
    assert!(second_page.contains(&"synthetic-0300".to_owned()));
    assert!(!second_page.contains(&"synthetic-0000".to_owned()));
    assert_eq!(second["nextCursor"], Value::Null);
    Ok(())
}
on_both_backends!(listing_pages_are_stable_under_inserts);

/// Copy `template`'s registration and classification under synthetic policy
/// CIDs whose closure is `authority`.
async fn insert_synthetic(
    h: &Harness,
    template: &str,
    authority: &[u8],
    cids: Vec<String>,
) -> anyhow::Result<()> {
    for cid in cids {
        for sql in [
            format!(
                "INSERT INTO policy_v3_registration (policy_cid, policy_bytes, policy_digest_hex, owner_did, policy_root_cid, enforcement_root_cid, content_source_digest_hex, native_projection_hash_hex, attested_enforcer_binding_bytes, registered_at, expires_at) SELECT '{cid}', policy_bytes, policy_digest_hex, owner_did, policy_root_cid, enforcement_root_cid, content_source_digest_hex, native_projection_hash_hex, attested_enforcer_binding_bytes, registered_at, expires_at FROM policy_v3_registration WHERE policy_cid = '{template}'"
            ),
            format!(
                "INSERT INTO policy_v3_owner_binding (policy_cid, state, authority_expires_at, unknown_reason, classifier_version, registered_mode, created_at) SELECT '{cid}', state, authority_expires_at, unknown_reason, classifier_version, registered_mode, created_at FROM policy_v3_owner_binding WHERE policy_cid = '{template}'"
            ),
        ] {
            h.execute(&sql).await?;
        }
        let insert = Query::insert()
            .into_table(Alias::new("policy_v3_owner_authority"))
            .columns([
                Alias::new("policy_cid"),
                Alias::new("delegation_id"),
                Alias::new("depth"),
            ])
            .values_panic([cid.into(), authority.to_vec().into(), 0i32.into()])
            .to_owned();
        h.conn().execute(h.backend().build(&insert)).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// N2: the root-lifetime cap, the record/enforce mode and the advertised mode.
// ---------------------------------------------------------------------------

fn boot(policy_v3: Value) -> Boot {
    Boot {
        policy_v3: Some(policy_v3),
    }
}

fn enforce_boot() -> Boot {
    boot(json!({"owner_authority_expiry": "enforce"}))
}

/// The process-wide value of a Prometheus counter series (0 when absent).
fn counter(name: &str, labels: &[(&str, &str)]) -> f64 {
    prometheus::gather()
        .iter()
        .filter(|family| family.get_name() == name)
        .flat_map(|family| family.get_metric())
        .filter(|metric| {
            labels.iter().all(|(key, value)| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.get_name() == *key && label.get_value() == *value)
            })
        })
        .map(|metric| metric.get_counter().get_value())
        .sum()
}

/// [F2][C2] Roots are capped at registration time + 31 days (+5 minutes of
/// skew) with `nbf <= exp`, in both modes; a root shaped like a released
/// SDK's is accepted.
async fn root_lifetime_is_capped_in_both_modes(backend: Backend) -> anyhow::Result<()> {
    for mode in ["record", "enforce"] {
        let Some(h) = Harness::with_boot(
            backend,
            Shape::KeySession,
            "root_lifetime_is_capped_in_both_modes",
            boot(json!({"owner_authority_expiry": mode})),
        )
        .await?
        else {
            return Ok(());
        };
        h.grant_owner(Window::until(now() + Duration::days(800)))
            .await?;
        let base = now();
        for (label, root) in [
            ("32 days", Window::until(base + Duration::days(32))),
            (
                "not before in a year, 30-day window",
                Window {
                    not_before: base + Duration::days(365),
                    expiry: base + Duration::days(395),
                    issued_at: None,
                },
            ),
            (
                "not before after expiry",
                Window {
                    not_before: base + Duration::days(2),
                    expiry: base + Duration::days(1),
                    issued_at: None,
                },
            ),
        ] {
            let refused = counter("tinycloud_policy_root_lifetime_refused_total", &[]);
            let (status, body, registered) = h.register(root).await?;
            assert_eq!(status, Status::Forbidden, "{mode} {label}: {body}");
            if root.not_before > now() {
                // A root that is not yet valid already fails the signed
                // time check that runs before the cap.
                assert_eq!(body, "policy-root-signature-invalid", "{mode} {label}");
            } else {
                assert_eq!(body, "policy-root-lifetime-exceeded", "{mode} {label}");
                assert!(
                    counter("tinycloud_policy_root_lifetime_refused_total", &[]) >= refused + 1.0
                );
            }
            assert_eq!(h.binding(&registered.policy_cid).await?, None);
        }
        // A released SDK signs `nbf` at signing time with `exp - nbf <= 31 d`.
        let signed_at = now() - Duration::seconds(10);
        let released = h
            .register_ok(Window {
                not_before: signed_at,
                expiry: signed_at + Duration::days(31),
                issued_at: None,
            })
            .await?;
        let binding = h.binding(&released.policy_cid).await?.expect("binding");
        assert_eq!(binding.registered_mode, mode);
    }
    Ok(())
}
on_both_backends!(root_lifetime_is_capped_in_both_modes);

/// A root that outlives its authority: `enforce` refuses it; `record`
/// stores it uncapped and counts it in the flip signal.
async fn enforce_refuses_roots_outliving_their_authority(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = Harness::with_boot(
        backend,
        Shape::KeySession,
        "enforce_refuses_roots_outliving_their_authority",
        enforce_boot(),
    )
    .await?
    else {
        return Ok(());
    };
    h.grant_owner(Window::until(now() + Duration::seconds(90)))
        .await?;
    let (status, body, registered) = h.register(policy_window()).await?;
    assert_eq!(status, Status::Forbidden, "{body}");
    assert_eq!(body, "policy-root-outlives-owner-authority");
    assert_eq!(h.binding(&registered.policy_cid).await?, None);

    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "enforce_refuses_roots_outliving_their_authority",
    )
    .await?
    else {
        return Ok(());
    };
    h.grant_owner(Window::until(now() + Duration::seconds(90)))
        .await?;
    let series = [("authority_ttl_bucket", "le_1h")];
    let exceeded = counter(
        "tinycloud_policy_owner_authority_expiry_exceeded_total",
        &series,
    );
    let policy = h.register_ok(policy_window()).await?;
    let binding = h.binding(&policy.policy_cid).await?.expect("binding");
    assert_eq!(binding.state, "bound-uncapped");
    assert_eq!(binding.registered_mode, "record");
    assert!(
        counter(
            "tinycloud_policy_owner_authority_expiry_exceeded_total",
            &series
        ) >= exceeded + 1.0
    );
    Ok(())
}
on_both_backends!(enforce_refuses_roots_outliving_their_authority);

/// [F9] Under `enforce`, an older grant that outlives the root is chosen
/// over a newer one that does not, so the registration is accepted.
async fn enforce_chooses_the_grant_that_outlives_the_root(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = Harness::with_boot(
        backend,
        Shape::PkhSession,
        "enforce_chooses_the_grant_that_outlives_the_root",
        enforce_boot(),
    )
    .await?
    else {
        return Ok(());
    };
    let long = h
        .grant_owner(Window::until(now() + Duration::days(2)).issued(now() - Duration::minutes(10)))
        .await?;
    h.grant_owner(Window::until(now() + Duration::hours(1)).issued(now() - Duration::minutes(1)))
        .await?;
    let policy = h.register_ok(policy_window()).await?;
    let binding = h.binding(&policy.policy_cid).await?.expect("binding");
    assert_eq!(binding.state, "bound");
    assert_eq!(binding.registered_mode, "enforce");
    assert_eq!(h.closure(&policy.policy_cid).await?, vec![long]);
    Ok(())
}
on_both_backends!(enforce_chooses_the_grant_that_outlives_the_root);

/// `GET /info` advertises the capability marker and exactly one mode.
async fn info_advertises_the_owner_authority_mode(backend: Backend) -> anyhow::Result<()> {
    for (boot, expected, absent) in [
        (
            Boot::default(),
            "policy-owner-authority-record",
            "policy-owner-authority-enforce",
        ),
        (
            enforce_boot(),
            "policy-owner-authority-enforce",
            "policy-owner-authority-record",
        ),
    ] {
        let Some(h) = Harness::with_boot(
            backend,
            Shape::KeySession,
            "info_advertises_the_owner_authority_mode",
            boot,
        )
        .await?
        else {
            return Ok(());
        };
        let response = h.client.get("/info").dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert!(response.headers().get_one("Cache-Control").is_none());
        let info: Value = response.into_json().await.unwrap();
        let features = info["features"].as_array().unwrap();
        let has = |feature: &str| features.iter().any(|value| value == feature);
        assert!(has("policy-owner-authority-v1"), "{info}");
        assert!(has(expected), "{info}");
        assert!(!has(absent), "{info}");
    }
    Ok(())
}
on_both_backends!(info_advertises_the_owner_authority_mode);

/// [F2] A legacy registration whose root outlives 31 days is classified as
/// before and counted, not refused.
async fn legacy_long_roots_are_counted_not_refused(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "legacy_long_roots_are_counted_not_refused",
    )
    .await?
    else {
        return Ok(());
    };
    let registered_at = now() - Duration::days(40);
    h.grant_owner(Window {
        not_before: registered_at - Duration::days(1),
        expiry: now() + Duration::days(2),
        issued_at: None,
    })
    .await?;
    let policy = h.register_ok(policy_window()).await?;
    h.forget_binding(&policy.policy_cid).await?;
    backdate(&h, &policy.policy_cid, registered_at).await?;
    let counted = counter("tinycloud_policy_legacy_root_lifetime_exceeded_total", &[]);
    let backfilled = counter(
        "tinycloud_policy_owner_binding_backfill_total",
        &[("outcome", "bound")],
    );
    let binding = h.classify_on_use(&policy).await?;
    assert_eq!(binding.registered_mode, "backfill");
    assert_eq!(binding.state, "bound");
    assert!(counter("tinycloud_policy_legacy_root_lifetime_exceeded_total", &[]) >= counted + 1.0);
    assert!(
        counter(
            "tinycloud_policy_owner_binding_backfill_total",
            &[("outcome", "bound")],
        ) >= backfilled + 1.0
    );
    Ok(())
}
on_both_backends!(legacy_long_roots_are_counted_not_refused);

/// [F6] A registration after the cutover with no classification (written by
/// an older binary) gets the lifetime cap, unlike a legacy one.
async fn post_cutover_unclassified_rows_get_the_lifetime_cap(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(mut h) = Harness::new(
        backend,
        Shape::KeySession,
        "post_cutover_unclassified_rows_get_the_lifetime_cap",
    )
    .await?
    else {
        return Ok(());
    };
    let registered_at = now() - Duration::days(40);
    h.grant_owner(Window {
        not_before: registered_at - Duration::days(1),
        expiry: now() + Duration::days(2),
        issued_at: None,
    })
    .await?;
    let policy = h.register_ok(policy_window()).await?;
    h.forget_binding(&policy.policy_cid).await?;
    backdate(&h, &policy.policy_cid, registered_at).await?;
    h.reboot(boot(json!({
        "legacy_cutover": format_time(now() - Duration::days(60)),
    })))
    .await?;
    let binding = h.classify_on_use(&policy).await?;
    assert_eq!(binding.registered_mode, "record");
    assert_eq!(binding.state, "unknown");
    assert_eq!(binding.unknown_reason.as_deref(), Some("lifetime-exceeded"));
    Ok(())
}
on_both_backends!(post_cutover_unclassified_rows_get_the_lifetime_cap);

/// [F6] Under `enforce`, a post-cutover unclassified row whose root outlives
/// its only authority is recorded `unknown`.
async fn post_cutover_rows_outliving_their_authority_are_unknown_under_enforce(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(mut h) = Harness::new(
        backend,
        Shape::KeySession,
        "post_cutover_rows_outliving_their_authority_are_unknown_under_enforce",
    )
    .await?
    else {
        return Ok(());
    };
    h.grant_owner(Window::until(now() + Duration::seconds(90)))
        .await?;
    let policy = h.register_ok(policy_window()).await?;
    assert_eq!(
        h.binding(&policy.policy_cid).await?.unwrap().state,
        "bound-uncapped"
    );
    h.forget_binding(&policy.policy_cid).await?;
    h.reboot(boot(json!({
        "owner_authority_expiry": "enforce",
        "legacy_cutover": format_time(now() - Duration::days(1)),
    })))
    .await?;
    let binding = h.classify_on_use(&policy).await?;
    assert_eq!(binding.registered_mode, "enforce");
    assert_eq!(binding.state, "unknown");
    assert_eq!(
        binding.unknown_reason.as_deref(),
        Some("outlives-authority")
    );
    Ok(())
}
on_both_backends!(post_cutover_rows_outliving_their_authority_are_unknown_under_enforce);
