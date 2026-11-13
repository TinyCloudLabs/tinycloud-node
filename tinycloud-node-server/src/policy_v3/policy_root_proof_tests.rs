//! TC-2958: a registered policy root is never invocation authority, cited
//! alone or beside other proofs. Reading the content, describing the
//! policy's key and authorizing a delivery all need ordinary authority or a
//! session minted under the policy's conditions.

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
/// enforcer's own root in either order.
fn root_proofs(root: Cid, own: Cid) -> [Vec<Cid>; 3] {
    [vec![root], vec![root, own], vec![own, root]]
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

/// The authenticated key describe refuses the enforcement root, which
/// carries the decrypt on the policy's key, alone or beside another proof.
async fn the_enforcement_root_describes_no_key(backend: Backend) -> anyhow::Result<()> {
    let ledger = tempfile::tempdir()?;
    let Some(mut h) = Harness::new_with(
        backend,
        Shape::KeySession,
        "the_enforcement_root_describes_no_key",
        |config| {
            config.encryption_network.named_keys_v1 = true;
            config.encryption_network.deletion_ledger_path =
                Some(ledger.path().join("deletion-ledger.jsonl"));
        },
    )
    .await?
    else {
        return Ok(());
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
        .await?
        .network_id;
    // The registration records the share key `share/<shareId>` its source names.
    let leaf = format!("{}/{KEY_PATH}", h.network);
    let mut grants = h.owner_grants();
    grants[2].0 = leaf.clone();
    h.grant_owner_with(&grants, Window::until(now() + Duration::days(2)))
        .await?;
    let (status, body, policy) = h
        .register_with(policy_window(), |policy| {
            policy["contentSource"]["shareId"] = json!("tc-2958");
            policy["contentSource"]["encryptionKeyPath"] = json!(KEY_PATH);
            policy["capabilityCeiling"][1]["resource"] = json!(leaf);
        })
        .await?;
    anyhow::ensure!(status == Status::Ok, "register: {status} {body}");
    let own = enforcer_own_root(&h).await?;
    let node = h.node_did();
    for proofs in root_proofs(policy.enforcement_root_cid.parse()?, own) {
        let authorization = invocation(
            &h.enforcer,
            &node,
            grant(&leaf, "tinycloud.encryption/decrypt")?,
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
    Ok(())
}
on_both_backends!(the_enforcement_root_describes_no_key);

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
