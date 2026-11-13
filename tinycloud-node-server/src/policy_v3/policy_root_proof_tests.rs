//! TC-2958: a registered policy root is never invocation authority, cited
//! alone or beside other proofs, by whichever encoding of its CID. Reading the
//! content, describing or decrypting under the policy's key and authorizing a
//! delivery all need ordinary authority or a session minted under the
//! policy's conditions.

use super::test_harness::*;
use super::*;
use rocket::{
    http::{ContentType, Header},
    local::asynchronous::Client,
};
use serde_json::json;
use std::collections::BTreeMap;
use tinycloud_auth::{
    siwe_recap::Ability as RecapAbility,
    ssi::{claims::jwt::NumericDate, ucan::Payload},
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::encryption_network::{CreateNetworkRequest, Threshold, KEY_DESCRIBE_TYPE};

type Cid = tinycloud_auth::ipld_core::cid::Cid;

const ROOT_REFUSED: &str = "policy-root-cannot-authorize-invocation";
const KEY_PATH: &str = "share/tc-2958";

/// An invocation by `signer`, addressed to `audience`, citing `proofs`.
fn invocation(
    signer: &Signer,
    audience: &str,
    attenuation: Capabilities<Value>,
    proofs: &[Cid],
    facts: Vec<Value>,
) -> anyhow::Result<String> {
    let Signer::Key { jwk, vm, .. } = signer else {
        anyhow::bail!("invocations are signed by keys");
    };
    let at = now();
    Ok(Payload {
        issuer: vm.parse()?,
        audience: audience.parse()?,
        not_before: Some(NumericDate::try_from_seconds(at.unix_timestamp() as f64)?),
        expiration: NumericDate::try_from_seconds(
            (at + Duration::seconds(30)).unix_timestamp() as f64
        )?,
        nonce: Some(unique("tc2958invoke")),
        facts: Some(facts),
        proof: proofs.to_vec(),
        attenuation,
    }
    .sign(Algorithm::EdDSA, jwk)?
    .encode()?)
}

fn grant(resource: &str, ability: &str) -> anyhow::Result<Capabilities<Value>> {
    let mut capabilities = Capabilities::<Value>::new();
    capabilities.with_action(
        resource.parse()?,
        ability.parse::<RecapAbility>()?,
        [BTreeMap::<String, Value>::new()],
    );
    Ok(capabilities)
}

/// The read a policy session is minted for: `kv/get` on the content under
/// the policy's exact selector.
fn policy_read(h: &Harness) -> anyhow::Result<Capabilities<Value>> {
    Ok(serde_json::from_value(
        attenuation_for_policy_capabilities(&[json!({
            "kind": "kv",
            "resource": h.content_resource.to_string(),
            "selector": "exact",
            "actions": ["tinycloud.kv/get"],
        })])
        .map_err(|(_, error)| anyhow::anyhow!(error))?,
    )?)
}

/// A root the enforcer issues to itself on a space of its own, which the
/// node admits like any owner's root.
async fn enforcer_own_root(h: &Harness) -> anyhow::Result<Cid> {
    let space = SpaceId::new(h.enforcer.did().parse::<DIDBuf>()?, "own".parse()?)?;
    let resource = space.to_resource("kv".parse()?, Some("x".parse()?), None, None);
    let delegation = h.enforcer.delegate(
        h.enforcer.did(),
        &[(resource.to_string(), "tinycloud.kv/get")],
        policy_window(),
        &[],
    )?;
    Ok(h.import(delegation).await?.parse()?)
}

/// Every proof list that cites a registered root: alone, and beside the
/// enforcer's own root in either order; each by the root's stored CID and by
/// the same multihash under another codec (dag-cbor), which names the same
/// delegation.
fn root_proofs(root: Cid, own: Cid) -> Vec<Vec<Cid>> {
    let alias = Cid::new_v1(0x71, *root.hash());
    [root, alias]
        .into_iter()
        .flat_map(|root| [vec![root], vec![root, own], vec![own, root]])
        .collect()
}

/// `/invoke` refuses a read citing either registered root, alone or beside
/// another proof.
async fn policy_roots_authorize_no_read(backend: Backend) -> anyhow::Result<()> {
    let Some(h) =
        Harness::new(backend, Shape::KeySession, "policy_roots_authorize_no_read").await?
    else {
        return Ok(());
    };
    h.grant_owner(policy_window()).await?;
    let policy = h.register_ok(policy_window()).await?;
    let own = enforcer_own_root(&h).await?;
    for root in [&policy.enforcement_root_cid, &policy.policy_root_cid] {
        for proofs in root_proofs(root.parse()?, own) {
            let response = h
                .client
                .post("/invoke")
                .header(Header::new(
                    "Authorization",
                    invocation(
                        &h.enforcer,
                        h.enforcer.did(),
                        policy_read(&h)?,
                        &proofs,
                        vec![],
                    )?,
                ))
                .dispatch()
                .await;
            let status = response.status();
            let body = response.into_string().await.unwrap_or_default();
            assert_eq!(
                (status, body.as_str()),
                (Status::Forbidden, ROOT_REFUSED),
                "{proofs:?}"
            );
        }
    }
    Ok(())
}
on_both_backends!(policy_roots_authorize_no_read);

/// A registered policy over the content whose source is a share key on the
/// owner's `default` network: the named key `share/tc-2958`, or the network
/// itself. The holder has a minted session.
struct KeyShare {
    h: Harness,
    network: tinycloud_core::encryption_network::NetworkId,
    key_path: Option<&'static str>,
    /// The decrypt resource: the key's URN, or the network's.
    resource: String,
    policy: Registered,
    session: Cid,
    own: Cid,
    /// The wrapped key the registration's source binds.
    wrapped: Vec<u8>,
    public_key: Vec<u8>,
    _ledger: tempfile::TempDir,
}

impl KeyShare {
    async fn new(
        backend: Backend,
        key_path: Option<&'static str>,
        test: &str,
    ) -> anyhow::Result<Option<Self>> {
        use tinycloud_core::encryption_network::{
            backend::wrap_to_public_key, canonical::canonical_hash,
        };
        let ledger = tempfile::tempdir()?;
        let Some(mut h) = Harness::new_with(backend, Shape::KeySession, test, |config| {
            config.encryption_network.named_keys_v1 = true;
            config.encryption_network.deletion_ledger_path =
                Some(ledger.path().join("deletion-ledger.jsonl"));
        })
        .await?
        else {
            return Ok(None);
        };
        h.network = format!("urn:tinycloud:encryption:{}:default", h.space_owner.did());
        let service = h
            .client
            .rocket()
            .state::<EncryptionService>()
            .expect("EncryptionService is managed");
        let network = service
            .create_one_of_one_network(CreateNetworkRequest {
                name: "default".into(),
                owner_did: h.space_owner.did().into(),
                threshold: Threshold::one_of_one(),
            })
            .await?;
        // A named source is the share key `share/<shareId>`, which the
        // registration records; the publisher encrypts to its public key.
        let public_key = match key_path {
            Some(path) => {
                service
                    .public_key(&KeyLocation::new(&network.network_id, path)?)
                    .await?
                    .public_encryption_key
            }
            None => network.public_encryption_key,
        };
        let network = network.network_id;
        let wrapped = wrap_to_public_key(&public_key, &[0xCD; 32])?;
        let resource = match key_path {
            Some(path) => format!("{}/{path}", h.network),
            None => h.network.clone(),
        };
        let mut grants = h.owner_grants();
        grants[2].0 = resource.clone();
        h.grant_owner_with(&grants, Window::until(now() + Duration::days(2)))
            .await?;
        // A named source binds the raw wrapped bytes; a network source binds
        // the signed wire form.
        let digest = match key_path {
            Some(_) => hex::encode(Sha256::digest(&wrapped)),
            None => canonical_hash(&json!(base64::encode(&wrapped))),
        };
        let (status, body, policy) = h
            .register_with(policy_window(), |policy| {
                policy["contentSource"]["shareId"] = json!("tc-2958");
                policy["contentSource"]["encryptedSymmetricKeyDigestHex"] = json!(digest);
                if let Some(path) = key_path {
                    policy["contentSource"]["encryptionKeyPath"] = json!(path);
                }
                policy["capabilityCeiling"][1]["resource"] = json!(resource);
            })
            .await?;
        anyhow::ensure!(status == Status::Ok, "register: {status} {body}");
        let session = session_cid(&h.mint_ok(&policy).await?)?;
        let own = enforcer_own_root(&h).await?;
        Ok(Some(Self {
            h,
            network,
            key_path,
            resource,
            policy,
            session,
            own,
            wrapped,
            public_key,
            _ledger: ledger,
        }))
    }

    /// A decrypt request for `wrapped` and the invocation fact that binds it.
    fn decrypt_request(&self, wrapped: &[u8]) -> (Value, Value) {
        use tinycloud_core::encryption_network::{
            canonical::canonical_hash, types::ALG_X25519_AES256GCM, DECRYPT_REQUEST_TYPE,
        };
        let wrapped = json!(base64::encode(wrapped));
        let receiver = json!(base64::encode(
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::random_from_rng(
                rand::rngs::OsRng
            ))
            .as_bytes()
        ));
        let mut body = json!({
            "type": DECRYPT_REQUEST_TYPE,
            "targetNode": self.h.node_did(),
            "networkId": self.h.network,
            "alg": ALG_X25519_AES256GCM,
            "keyVersion": 1,
            "encryptedSymmetricKeyHash": canonical_hash(&wrapped),
            "encryptedSymmetricKey": wrapped,
            "receiverPublicKeyHash": canonical_hash(&receiver),
            "receiverPublicKey": receiver,
        });
        if let Some(path) = self.key_path {
            body["keyPath"] = json!(path);
        }
        let mut fact = body.clone();
        let object = fact.as_object_mut().expect("object");
        object.remove("encryptedSymmetricKey");
        object.remove("receiverPublicKey");
        fact["bodyHash"] = json!(canonical_hash(&body));
        (body, fact)
    }

    /// A wrapped key other than the one the registration's source binds.
    fn other_wrapped(&self) -> anyhow::Result<Vec<u8>> {
        Ok(
            tinycloud_core::encryption_network::backend::wrap_to_public_key(
                &self.public_key,
                &[0xEE; 32],
            )?,
        )
    }

    /// `signer` asks `route` to decrypt `wrapped`, citing `proofs`.
    async fn decrypt(
        &self,
        route: &str,
        signer: &Signer,
        proofs: &[Cid],
        wrapped: &[u8],
    ) -> anyhow::Result<(Status, String)> {
        let (body, fact) = self.decrypt_request(wrapped);
        let authorization = invocation(
            signer,
            &self.h.node_did(),
            grant(&self.resource, "tinycloud.encryption/decrypt")?,
            proofs,
            vec![fact, Value::Null],
        )?;
        let response = self
            .h
            .client
            .post(route)
            .header(ContentType::JSON)
            .header(Header::new("Authorization", authorization))
            .body(body.to_string())
            .dispatch()
            .await;
        let status = response.status();
        Ok((status, response.into_string().await.unwrap_or_default()))
    }

    /// The routes a decrypt of this source is served on: `/invoke`, and for a
    /// network source the network's own decrypt route.
    fn decrypt_routes(&self) -> Vec<String> {
        let mut routes = vec!["/invoke".to_owned()];
        if self.key_path.is_none() {
            routes.push(format!("/encryption/networks/{}/decrypt", self.network));
        }
        routes
    }

    /// On every decrypt route, the enforcement root is refused in every
    /// citing form, whether or not the request matches the registered
    /// source; the holder's session, cited by its stored CID or by a codec
    /// alias, is still held to the registered source.
    async fn assert_decrypts(&self) -> anyhow::Result<()> {
        let root: Cid = self.policy.enforcement_root_cid.parse()?;
        let other = self.other_wrapped()?;
        for route in self.decrypt_routes() {
            for proofs in root_proofs(root, self.own) {
                for wrapped in [&self.wrapped, &other] {
                    assert_eq!(
                        self.decrypt(&route, &self.h.enforcer, &proofs, wrapped)
                            .await?,
                        (Status::Forbidden, ROOT_REFUSED.to_owned()),
                        "{route} {proofs:?}"
                    );
                }
            }
            for session in [self.session, Cid::new_v1(0x71, *self.session.hash())] {
                assert_eq!(
                    self.decrypt(&route, &self.h.holder, &[session], &other)
                        .await?,
                    (
                        Status::Forbidden,
                        "policy-decrypt-content-source-mismatch".to_owned()
                    ),
                    "{route} {session}"
                );
            }
        }
        Ok(())
    }
}

/// A named share key: the enforcement root, cited in any form, neither
/// describes the key nor decrypts under it.
async fn the_enforcement_root_neither_describes_nor_decrypts_a_named_key(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(share) = KeyShare::new(
        backend,
        Some(KEY_PATH),
        "the_enforcement_root_neither_describes_nor_decrypts_a_named_key",
    )
    .await?
    else {
        return Ok(());
    };
    let h = &share.h;
    let node = h.node_did();
    let network = &share.network;
    for proofs in root_proofs(share.policy.enforcement_root_cid.parse()?, share.own) {
        let authorization = invocation(
            &h.enforcer,
            &node,
            grant(&share.resource, "tinycloud.encryption/decrypt")?,
            &proofs,
            vec![json!({
                "type": KEY_DESCRIBE_TYPE,
                "targetNode": node,
                "networkId": network.to_string(),
                "keyPath": KEY_PATH,
            })],
        )?;
        let response = h
            .client
            .get(format!("/encryption/networks/{network}/keys/{KEY_PATH}"))
            .header(Header::new("Authorization", authorization))
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        assert_eq!(
            (status, body.as_str()),
            (Status::Forbidden, ROOT_REFUSED),
            "{proofs:?}"
        );
    }
    share.assert_decrypts().await
}
on_both_backends!(the_enforcement_root_neither_describes_nor_decrypts_a_named_key);

/// A network source: the enforcement root, cited in any form, decrypts
/// nothing on `/invoke` or on the network's decrypt route.
async fn the_enforcement_root_decrypts_nothing_on_the_network(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(share) = KeyShare::new(
        backend,
        None,
        "the_enforcement_root_decrypts_nothing_on_the_network",
    )
    .await?
    else {
        return Ok(());
    };
    share.assert_decrypts().await
}
on_both_backends!(the_enforcement_root_decrypts_nothing_on_the_network);

async fn authorize_delivery_with(
    client: &Client,
    authorization: String,
    body: String,
) -> (Status, String) {
    let response = client
        .post("/policy/v3/deliveries/authorize")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", authorization))
        .body(body)
        .dispatch()
        .await;
    let status = response.status();
    (status, response.into_string().await.unwrap_or_default())
}

/// A delivery authorization refuses the enforcement root, alone or beside
/// another proof, before the share record is read; the policy owner's own
/// read grant is authorized for the same share.
async fn delivery_authorization_refuses_the_enforcement_root(
    backend: Backend,
) -> anyhow::Result<()> {
    use crate::delivery_link::test_support::{b64, build, millis, StubLinks, LINK_ID, ORIGIN};
    let Some(h) = Harness::new(
        backend,
        Shape::KeySession,
        "delivery_authorization_refuses_the_enforcement_root",
    )
    .await?
    else {
        return Ok(());
    };
    let owner_grant: Cid = h.grant_owner(policy_window()).await?.parse()?;
    let policy = h.register_ok(policy_window()).await?;
    let own = enforcer_own_root(&h).await?;

    // The production app reads share records from the links API; this app
    // serves the delivery route on the same database and runtime, with the
    // record held in memory.
    let runtime = h
        .client
        .rocket()
        .state::<PolicyV3Runtime>()
        .expect("policy runtime")
        .clone();
    let registration = policy_v3_registration::Entity::find_by_id(policy.policy_cid.clone())
        .one(&runtime.conn)
        .await?
        .ok_or_else(|| anyhow::anyhow!("registration row"))?;
    let invitation_public_key = b64(&runtime.signer.share_invitation_public_key());
    let links = Arc::new(StubLinks::default());
    let runtime = runtime.with_delivery(
        &ShareEmailConfig {
            enabled: true,
            target_origin: "https://node.example".into(),
            return_origin: ORIGIN.into(),
            email_origin: Some("https://witness.credentials.org".into()),
            invitation_public_key: Some(invitation_public_key),
            links_fetch_per_invoker_per_minute: 100,
            links_fetch_global_per_minute: 100,
            ..ShareEmailConfig::default()
        },
        links.clone(),
    )?;
    let client = Client::tracked(
        rocket::build()
            .mount("/", rocket::routes![authorize_delivery])
            .manage(runtime),
    )
    .await?;

    let policy_value: Value = serde_json::from_slice(&registration.policy_bytes)?;
    let binding: Value = serde_json::from_slice(&registration.attested_enforcer_binding_bytes)?;
    let mut envelope = json!({
        "version": 3,
        "recipientMatcher": {"kind": "exactEmail", "value": "alice@example.test"},
        "actions": ["read"],
        "target": {"origin": "https://node.example", "nodeAudience": binding["nodeAudience"]},
        "policy": policy_value,
        "policyCid": registration.policy_cid,
        "policyRoot": {"cid": registration.policy_root_cid},
        "enforcementRoot": {"cid": registration.enforcement_root_cid},
        "attestedEnforcerBinding": binding,
        "contentSource": policy_value["contentSource"],
        "contentSourceDigestHex": registration.content_source_digest_hex,
        "expiry": registration.expires_at,
        "display": {"filename": "document.txt"},
    });
    let Signer::Key { keypair, .. } = &h.owner else {
        unreachable!()
    };
    let mut preimage = b"xyz.tinycloud.share/envelope/v3\0".to_vec();
    preimage.extend_from_slice(&canonical_json_value(&envelope));
    envelope["signature"] = json!({
        "algorithm": "Ed25519",
        "signerDid": h.owner.did(),
        "value": b64(&keypair.sign(&Sha256::digest(preimage))),
    });
    let link = build(
        &canonical_json_value(&envelope),
        keypair,
        &millis(OffsetDateTime::now_utc() + Duration::hours(1)),
    );
    links.put(LINK_ID, &link);
    let request = |jti: u8| -> anyhow::Result<String> {
        let mut request = DeliveryAuthorizationRequest {
            share_url: link.href.clone(),
            recipient_email: "alice@example.test".into(),
            document_name: "document.txt".into(),
            jti: b64(&[jti; 16]),
            expires_at: millis(OffsetDateTime::now_utc() + Duration::minutes(4)),
            request_body_digest: String::new(),
        };
        request.request_body_digest = delivery_request_digest(&request)
            .map_err(|_| anyhow::anyhow!("delivery request digest"))?;
        Ok(serde_json::to_string(&request)?)
    };

    for (jti, proofs) in (1u8..).zip(root_proofs(policy.enforcement_root_cid.parse()?, own)) {
        let authorization = invocation(
            &h.enforcer,
            h.enforcer.did(),
            policy_read(&h)?,
            &proofs,
            vec![],
        )?;
        assert_eq!(
            authorize_delivery_with(&client, authorization, request(jti)?).await,
            (
                Status::Forbidden,
                "delivery-authorization-invalid".to_owned()
            ),
            "{proofs:?}"
        );
    }
    assert_eq!(links.fetch_count(), 0);

    let authorization = invocation(
        &h.owner,
        h.owner.did(),
        grant(&h.content_resource.to_string(), "tinycloud.kv/get")?,
        &[owner_grant],
        vec![],
    )?;
    let (status, body) = authorize_delivery_with(&client, authorization, request(9)?).await;
    assert_eq!(status, Status::Ok, "{body}");
    Ok(())
}
on_both_backends!(delivery_authorization_refuses_the_enforcement_root);
