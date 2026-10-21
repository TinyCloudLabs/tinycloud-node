//! TC-1423: a Policy/v3 test harness over the production app, on SQLite and
//! on PostgreSQL: principals (did:key and did:pkh), owner grants, policy
//! registration, sessions, reads, decrypts, re-shares and revocations.
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
use tinycloud_core::sea_orm::{ConnectOptions, Database};

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

pub(super) fn unique(label: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "{label}{}x{}x{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos() % 1_000_000_000_000,
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

/// A database the production app is booted on.
pub(super) struct TestDatabase {
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
        Ok(Some(Self { url, _dir: dir }))
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
}

impl Window {
    pub fn until(expiry: OffsetDateTime) -> Self {
        Self {
            not_before: now() - Duration::seconds(30),
            expiry,
        }
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
                    window.not_before,
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
        self.revoke_citing(cid, &[])
    }

    /// An encoded revocation of `cid` citing `proofs` (a revoke control).
    pub fn revoke_citing(&self, cid: &str, proofs: &[Cid]) -> anyhow::Result<String> {
        match self {
            Self::Key { jwk, vm, did, .. } => Ok(TinyCloudRevocation::Ucan(Box::new(
                Payload {
                    issuer: vm.parse()?,
                    audience: did.parse()?,
                    not_before: None,
                    expiration: seconds(now() + Duration::seconds(60))?,
                    nonce: Some(unique("tc1423revoke")),
                    facts: Some(Vec::new()),
                    proof: proofs.to_vec(),
                    attenuation: capabilities(&[(
                        format!("urn:cid:{cid}"),
                        "tinycloud.delegation/revoke",
                    )])?,
                }
                .sign(Algorithm::EdDSA, jwk)?,
            ))
            .encode()?),
            Self::Pkh { .. } => {
                anyhow::ensure!(proofs.is_empty(), "SIWE fixtures carry no proofs");
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
        self.invoke_for(self.did(), attenuation, proof)
    }

    /// An encoded invocation addressed to `audience`.
    pub fn invoke_for(
        &self,
        audience: &str,
        attenuation: Capabilities<Value>,
        proof: Cid,
    ) -> anyhow::Result<String> {
        let Self::Key { jwk, vm, .. } = self else {
            anyhow::bail!("invocations are signed by keys");
        };
        let at = now();
        Ok(Payload {
            issuer: vm.parse()?,
            audience: audience.parse()?,
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

#[derive(Debug, Clone)]
pub(super) struct Registered {
    pub policy_cid: String,
    pub policy_root_cid: String,
    pub enforcement_root_cid: String,
}

/// Which principal owns the content space, and who owns the policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Shape {
    /// A did:key space owner delegates (UCAN) to the policy owner's key.
    KeySession,
    /// A did:pkh space owner signs SIWE to the policy owner's key, as Share
    /// and the CLI do.
    PkhSession,
}

pub(super) struct Harness {
    pub client: Client,
    /// Kept for the app's lifetime (the SQLite directory).
    _db: TestDatabase,
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

impl Harness {
    pub async fn new(backend: Backend, shape: Shape, test: &str) -> anyhow::Result<Option<Self>> {
        Self::new_with_held(backend, shape, test, false).await
    }

    /// Same harness, with the held-credentials flag set. An enabled flag needs an audience.
    pub async fn new_with_held(
        backend: Backend,
        shape: Shape,
        test: &str,
        held: bool,
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
        let client = Self::boot_app(&db, &vector, &issuer, held).await?;
        let harness = Self {
            client,
            _db: db,
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
        held: bool,
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
        config.held_credentials = crate::config::HeldCredentialsConfig {
            enabled: held,
            audience: held.then(|| "relying-party.example".to_owned()),
        };
        let figment = Figment::from(rocket::Config {
            address: "127.0.0.1".parse()?,
            log_level: rocket::config::LogLevel::Off,
            ..rocket::Config::default()
        })
        .merge(Serialized::defaults(&config));
        let config: crate::config::Config = figment.extract()?;
        Ok(Client::tracked(crate::app_with_control(&figment, &config, None).await?).await?)
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
        vec![self.requested_kv(), self.requested_decrypt()]
    }

    fn requested_kv(&self) -> Value {
        json!({
            "kind": "kv",
            "resource": self.content_resource.to_string(),
            "selector": "exact",
            "actions": [KV_GET],
        })
    }

    fn requested_decrypt(&self) -> Value {
        json!({
            "kind": "encryption",
            "resource": self.network,
            "action": DECRYPT,
        })
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
            // The policy may outlive its roots; the roots' expiry is what
            // the tests exercise.
            "expiresAt": format_time(root.expiry + Duration::hours(1)),
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
        let enforcement_root_cid = decode_root(&enforcement_root)
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
                enforcement_root_cid,
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

    /// POST a shape-valid held presentation (`{sdJwt, siwe}`) to the mint
    /// route after a fresh challenge. Used where the verifier must not run
    /// (the held flag is off), so the body needs only the held shape.
    pub async fn mint_held_presentation(
        &self,
        policy: &Registered,
    ) -> anyhow::Result<(Status, String)> {
        let (status, body) = self.challenge(policy).await;
        if status != Status::Ok {
            return Ok((status, body));
        }
        let challenge: Value = serde_json::from_str(&body)?;
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
                    "presentation": {
                        "sdJwt": "held-placeholder~",
                        "siwe": {"message": "placeholder", "signature": "0x00"}
                    },
                    "requestedExpiresAt": format_time(now() + Duration::seconds(300)),
                })
                .to_string(),
            )
            .dispatch()
            .await;
        let status = response.status();
        Ok((status, response.into_string().await.unwrap_or_default()))
    }

    /// A held-shaped request whose `credential` field is set. The request-shape gate
    /// refuses it before any verifier work.
    pub async fn mint_held_with_credential(
        &self,
        policy: &Registered,
    ) -> anyhow::Result<(Status, String)> {
        let (status, body) = self.challenge(policy).await;
        if status != Status::Ok {
            return Ok((status, body));
        }
        let challenge: Value = serde_json::from_str(&body)?;
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
                    "accountAuthorizationCid": "placeholder",
                    "credentialSpaceId": "placeholder",
                    "credential": {},
                    "presentation": {
                        "sdJwt": "held-placeholder~",
                        "siwe": {"message": "placeholder", "signature": "0x00"}
                    },
                    "requestedExpiresAt": format_time(now() + Duration::seconds(300)),
                })
                .to_string(),
            )
            .dispatch()
            .await;
        let status = response.status();
        Ok((status, response.into_string().await.unwrap_or_default()))
    }

    /// The holder reads the content under a minted session.
    pub async fn read(&self, session: &str) -> anyhow::Result<(Status, Vec<u8>)> {
        let s0 = decode_delegation(session).map_err(|(_, error)| anyhow::anyhow!(error))?;
        let invocation = self.holder.invoke(
            serde_json::from_value(
                attenuation_for_policy_capabilities(&[self.requested_kv()])
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

    /// `POST /revoke` with an encoded revocation.
    pub async fn post_revoke(&self, authorization: String) -> (Status, String) {
        let response = self
            .client
            .post("/revoke")
            .header(Header::new("Authorization", authorization))
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    /// `POST /revoke` with a `RootRevocation/v1` signed by `issuer` (Ed25519).
    pub async fn revoke_root_json(
        &self,
        issuer: &Signer,
        root_cid: &str,
        role: &str,
    ) -> anyhow::Result<(Status, String)> {
        let mut revocation = json!({
            "schema": ROOT_REVOCATION_V1_SCHEMA,
            "targetCid": root_cid,
            "targetRole": role,
            "ownerDid": self.owner.did(),
            "nodeAudience": self.node_did(),
            "revokedAt": format_time(now()),
            "reason": "tc-1423-test",
            "issuerDid": issuer.did(),
        });
        let mut preimage = b"xyz.tinycloud.policy/RootRevocation/v1\0".to_vec();
        preimage.extend_from_slice(&canonical_json_value(&revocation));
        revocation["signature"] = json!({
            "suite": "Ed25519",
            "signerDid": issuer.did(),
            "value": encode_config(issuer.keypair().sign(&Sha256::digest(preimage)), URL_SAFE_NO_PAD),
        });
        let response = self
            .client
            .post("/revoke")
            .header(ContentType::JSON)
            .body(json!({"revocation": revocation}).to_string())
            .dispatch()
            .await;
        let status = response.status();
        Ok((status, response.into_string().await.unwrap_or_default()))
    }

    /// `POST /policy/v3/status` (renewal) for `root_cid`.
    pub async fn renew_status(&self, root_cid: &str) -> (Status, String) {
        let response = self
            .client
            .post("/policy/v3/status")
            .header(ContentType::JSON)
            .body(json!({"rootCid": root_cid, "renewal": {}}).to_string())
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }
}

pub(super) fn policy_window() -> Window {
    Window::until(now() + Duration::days(1))
}

pub(super) fn session_cid(session: &str) -> anyhow::Result<Cid> {
    Ok(decode_delegation(session)
        .map_err(|(_, error)| anyhow::anyhow!(error))?
        .content_hash()
        .to_cid(0x55))
}

pub(super) fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

impl Harness {
    /// The holder decrypts through the network route under a session.
    pub async fn decrypt(&self, session: &str) -> anyhow::Result<(Status, String)> {
        let invocation = self.holder.invoke_for(
            &self.node_did(),
            serde_json::from_value(
                attenuation_for_policy_capabilities(&[self.requested_decrypt()])
                    .map_err(|(_, error)| anyhow::anyhow!(error))?,
            )?,
            session_cid(session)?,
        )?;
        let response = self
            .client
            .post(format!("/encryption/networks/{}/decrypt", self.network))
            .header(ContentType::JSON)
            .header(Header::new("Authorization", invocation))
            .body("{}")
            .dispatch()
            .await;
        let status = response.status();
        Ok((status, response.into_string().await.unwrap_or_default()))
    }

    /// The holder re-shares a session to a fresh reader; returns the reader
    /// and the child CID.
    pub async fn reshare(
        &self,
        session: &str,
    ) -> anyhow::Result<(Status, String, Signer, Option<Cid>)> {
        let s0 = decode_delegation(session).map_err(|(_, error)| anyhow::anyhow!(error))?;
        let reader = Signer::key();
        let child_not_before = s0.0.not_before.unwrap().unix_timestamp() + 1;
        let mut facts = match &s0.0.delegation {
            TinyCloudDelegation::Ucan(ucan) => ucan.payload().facts.clone().unwrap(),
            TinyCloudDelegation::Cacao(_) => unreachable!(),
        };
        facts[0]["remainingRedelegationDepth"] = json!(7);
        let Signer::Key { jwk, vm, .. } = &self.holder else {
            unreachable!()
        };
        let child = Payload {
            issuer: vm.parse()?,
            audience: reader.did().parse()?,
            // Whole seconds (sub-microsecond times don't survive PostgreSQL
            // timestamps), after the parent's start; we wait for it below.
            not_before: Some(NumericDate::try_from_seconds(child_not_before as f64)?),
            expiration: NumericDate::try_from_seconds(
                (s0.0.expiry.unwrap().unix_timestamp() - 1) as f64,
            )?,
            nonce: Some(unique("tc1423child")),
            facts: Some(facts),
            proof: vec![s0.content_hash().to_cid(0x55)],
            attenuation: serde_json::from_value(
                attenuation_for_policy_capabilities(&[self.requested_kv()])
                    .map_err(|(_, error)| anyhow::anyhow!(error))?,
            )?,
        }
        .sign(Algorithm::EdDSA, jwk)?;
        // The child must be valid when it is imported.
        let wait = child_not_before - OffsetDateTime::now_utc().unix_timestamp();
        if wait >= 0 {
            tokio::time::sleep(std::time::Duration::from_millis(wait as u64 * 1000 + 50)).await;
        }
        let (status, body) = self
            .delegate(TinyCloudDelegation::Ucan(Box::new(child)).encode()?)
            .await;
        let cid = (status == Status::Ok)
            .then(|| serde_json::from_str::<Value>(&body).ok())
            .flatten()
            .and_then(|value| value["cid"].as_str().and_then(|cid| cid.parse().ok()));
        Ok((status, body, reader, cid))
    }

    /// `reader` reads under the re-shared child `child`.
    pub async fn read_as(&self, reader: &Signer, child: Cid) -> anyhow::Result<(Status, String)> {
        let invocation = reader.invoke(
            serde_json::from_value(
                attenuation_for_policy_capabilities(&[self.requested_kv()])
                    .map_err(|(_, error)| anyhow::anyhow!(error))?,
            )?,
            child,
        )?;
        let response = self
            .client
            .post("/invoke")
            .header(Header::new("Authorization", invocation))
            .dispatch()
            .await;
        let status = response.status();
        Ok((
            status,
            text(&response.into_bytes().await.unwrap_or_default()),
        ))
    }

    /// `/delegation/status` on `cid`, invoked by `signer`.
    pub async fn delegation_status(&self, signer: &Signer, cid: &str) -> anyhow::Result<Value> {
        let Signer::Key { jwk, vm, did, .. } = signer else {
            anyhow::bail!("status is invoked by keys");
        };
        let at = now();
        let invocation = Payload {
            issuer: vm.parse()?,
            audience: did.parse()?,
            not_before: Some(seconds(at)?),
            expiration: seconds(at + Duration::seconds(30))?,
            nonce: Some(unique("tc1423status")),
            facts: Some(Vec::<Value>::new()),
            proof: Vec::new(),
            attenuation: capabilities(&[(
                format!("urn:cid:{cid}"),
                "tinycloud.delegation/status",
            )])?,
        }
        .sign(Algorithm::EdDSA, jwk)?
        .encode()?;
        let response = self
            .client
            .post("/delegation/status")
            .header(ContentType::JSON)
            .header(Header::new("Authorization", invocation))
            .body(json!({"cid": cid}).to_string())
            .dispatch()
            .await;
        Ok(response.into_json().await.unwrap_or(Value::Null))
    }

    pub async fn root_status(&self, root_cid: &str) -> Value {
        self.client
            .get(format!("/policy/v3/status/{root_cid}"))
            .dispatch()
            .await
            .into_json()
            .await
            .unwrap_or(Value::Null)
    }
}

impl Harness {
    /// The holder mints a hook ticket on the content prefix citing `proofs`.
    pub async fn hook_ticket(&self, proofs: &[String]) -> anyhow::Result<(Status, String)> {
        let resource = self.content_space.clone().to_resource(
            "hooks".parse()?,
            Some("kv/shares".parse()?),
            None,
            None,
        );
        let Signer::Key { jwk, vm, did, .. } = &self.holder else {
            unreachable!()
        };
        let at = now();
        let invocation = Payload {
            issuer: vm.parse()?,
            audience: did.parse()?,
            not_before: Some(seconds(at)?),
            expiration: seconds(at + Duration::seconds(60))?,
            nonce: Some(unique("tc1423hooks")),
            facts: Some(Vec::<Value>::new()),
            proof: proofs
                .iter()
                .map(|cid| cid.parse())
                .collect::<Result<_, _>>()?,
            attenuation: capabilities(&[(resource.to_string(), "tinycloud.hooks/subscribe")])?,
        }
        .sign(Algorithm::EdDSA, jwk)?
        .encode()?;
        let response = self
            .client
            .post("/hooks/tickets")
            .header(ContentType::JSON)
            .header(Header::new("Authorization", invocation))
            .body(
                json!({
                    "subscriptions": [{
                        "space": self.content_space.to_string(),
                        "service": "kv",
                        "pathPrefix": "shares",
                    }],
                    "ttlSeconds": 120,
                })
                .to_string(),
            )
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        Ok((status, body))
    }
}
