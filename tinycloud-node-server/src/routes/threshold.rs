//! Threshold network authorization set routes (TC-2225). Mounted only when
//! `encryption_network.threshold_v1` is on; off, both paths answer 404.
//!
//! - `GET /threshold/<network>/chain`: the network's `cert` and `activation`
//!   objects, which anyone may read. Revocations and key-state statements are
//!   never served here.
//! - `POST /threshold/<network>/objects`: push one object. A held object is
//!   answered with the member's signed acknowledgement.

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use rocket::{http::Status, serde::json::Json, Route, State};
use serde::{Deserialize, Serialize};
use tinycloud_core::encryption_network::{
    threshold_set::{check_nonce, AcceptError, Ack, ObjectKind, Source, ThresholdSet},
    NetworkId,
};

use super::public::{ClientIp, RateLimiter};

/// The threshold routes, for the caller to mount when `threshold_v1` is on.
pub fn threshold_routes() -> Vec<Route> {
    rocket::routes![threshold_chain, threshold_push]
}

/// One object of the set as served.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainObject {
    kind: String,
    cid: String,
    /// base64url (no padding) of the object's bytes.
    object: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainView {
    network: String,
    objects: Vec<ChainObject>,
}

/// A pushed object.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushBody {
    kind: String,
    /// base64url (no padding) of the object's bytes.
    object: String,
    /// The client's nonce, echoed in the signed acknowledgement.
    nonce: String,
}

/// The network id from the path, which must be canonical.
fn network(network_id: &str) -> Result<NetworkId, (Status, String)> {
    let network = network_id
        .parse::<NetworkId>()
        .map_err(|err| (Status::BadRequest, err.to_string()))?;
    if network.to_string() != network_id {
        return Err((
            Status::BadRequest,
            "network id must be in canonical form".to_string(),
        ));
    }
    Ok(network)
}

#[get("/threshold/<network_id>/chain")]
pub async fn threshold_chain(
    network_id: &str,
    client_ip: ClientIp,
    rate_limiter: &State<RateLimiter>,
    set: &State<ThresholdSet>,
) -> Result<Json<ChainView>, (Status, String)> {
    rate_limiter
        .check(client_ip.0)
        .map_err(|status| (status, "Rate limit exceeded".to_string()))?;
    let network = network(network_id)?;
    let objects = set
        .chain(&network)
        .await
        .map_err(|_| (Status::InternalServerError, "database error".to_string()))?
        .into_iter()
        .map(|(kind, cid, bytes)| ChainObject {
            kind,
            cid,
            object: encode_config(bytes, URL_SAFE_NO_PAD),
        })
        .collect();
    Ok(Json(ChainView {
        network: network.to_string(),
        objects,
    }))
}

#[post("/threshold/<network_id>/objects", format = "json", data = "<body>")]
pub async fn threshold_push(
    network_id: &str,
    body: Json<PushBody>,
    client_ip: ClientIp,
    rate_limiter: &State<RateLimiter>,
    set: &State<ThresholdSet>,
) -> Result<Json<Ack>, (Status, String)> {
    rate_limiter
        .check(client_ip.0)
        .map_err(|status| (status, "Rate limit exceeded".to_string()))?;
    let network = network(network_id)?;
    let body = body.into_inner();
    check_nonce(&body.nonce).map_err(|error| (Status::BadRequest, error))?;
    let kind = ObjectKind::parse(&body.kind)
        .ok_or_else(|| (Status::BadRequest, "unknown object kind".to_string()))?;
    let bytes = decode_config(&body.object, URL_SAFE_NO_PAD)
        .map_err(|_| (Status::BadRequest, "object must be base64url".to_string()))?;
    let accepted = set
        .accept(&network, kind, &bytes, Source::Client)
        .await
        .map_err(|error| match error {
            AcceptError::Refused(_) => (Status::UnprocessableEntity, error.to_string()),
            AcceptError::Unavailable(_) => (Status::Conflict, error.to_string()),
            AcceptError::Db(_) => (Status::InternalServerError, "database error".to_string()),
        })?;
    set.ack(&network, &body.nonce, &accepted)
        .map(Json)
        .map_err(|error| (Status::InternalServerError, error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::{http::ContentType, local::asynchronous::Client};
    use serde_json::{json, Value};
    use tinycloud_core::migrations::Migrator;
    use tinycloud_core::sea_orm::{ConnectOptions, Database};
    use tinycloud_core::sea_orm_migration::MigratorTrait;
    use tinycloud_core::{
        encryption_network::threshold_set::{
            ack_preimage, encode_activation, encode_cert, object_cid, ActivationObject,
        },
        keys::{public_key_to_did_key, Keypair, StaticSecret},
    };
    use tinycloud_threshold::{
        activation_preimage, readiness_preimage, CertificateBody, ReadinessReceipt,
        SignedCertificate, SignedStatement,
    };

    const NETWORK: &str =
        "urn:tinycloud:encryption:did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK:vault";

    async fn client() -> Client {
        let mut options = ConnectOptions::new("sqlite::memory:".to_string());
        options.max_connections(1).sqlx_logging(false);
        let db = Database::connect(options).await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let keypair = tinycloud_core::keys::StaticSecret::new(vec![0x44; 32])
            .unwrap()
            .node_keypair();
        let rocket = rocket::build()
            .mount("/", threshold_routes())
            .manage(ThresholdSet::new(db, keypair, None))
            .manage(RateLimiter::with_rate(600, 100));
        Client::tracked(rocket).await.unwrap()
    }

    async fn push(client: &Client, body: Value) -> (Status, String) {
        push_to(client, NETWORK, body).await
    }

    async fn push_to(client: &Client, network: &str, body: Value) -> (Status, String) {
        let response = client
            .post(format!("/threshold/{network}/objects"))
            .remote("127.0.0.1:9000".parse().unwrap())
            .header(ContentType::JSON)
            .body(body.to_string())
            .dispatch()
            .await;
        (
            response.status(),
            response.into_string().await.unwrap_or_default(),
        )
    }

    #[rocket::async_test]
    async fn an_invalid_object_is_refused_and_nothing_is_served() {
        let client = client().await;
        let object = encode_config(b"not a certificate", URL_SAFE_NO_PAD);
        let (status, text) = push(
            &client,
            json!({"kind": "cert", "object": object, "nonce": "n-1"}),
        )
        .await;
        assert_eq!(status, Status::UnprocessableEntity);
        assert!(text.contains("threshold_object_refused"), "{text}");
        let (status, _) = push(
            &client,
            json!({"kind": "cert", "object": object, "nonce": ""}),
        )
        .await;
        assert_eq!(status, Status::BadRequest);
        let (status, _) = push(
            &client,
            json!({"kind": "erasure", "object": object, "nonce": "n-1"}),
        )
        .await;
        assert_eq!(status, Status::BadRequest);

        let response = client
            .get(format!("/threshold/{NETWORK}/chain"))
            .remote("127.0.0.1:9000".parse().unwrap())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let chain: Value = response.into_json().await.unwrap();
        assert_eq!(chain, json!({"network": NETWORK, "objects": []}));
    }

    const CHAIN: &str = include_str!("../../../tinycloud-threshold/vectors/v1/chain.json");

    fn keypair(seed: u8) -> Keypair {
        StaticSecret::new(vec![seed; 32]).unwrap().node_keypair()
    }

    fn did(keypair: &Keypair) -> String {
        public_key_to_did_key(keypair.public())
    }

    fn put(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    /// The genesis 2-of-3 certificate body of the shared vectors, with its
    /// network, owner and member DIDs replaced.
    fn genesis(network: &NetworkId, members: [&str; 3]) -> CertificateBody {
        let vectors: Value = serde_json::from_str(CHAIN).unwrap();
        let v = hex::decode(
            vectors["cases"][0]["inputs"]["certificate"]["body"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let skip_lp =
            |at: usize| at + 4 + u32::from_be_bytes(v[at..at + 4].try_into().unwrap()) as usize;
        let mut at = skip_lp(skip_lp(1));
        // rekey, epoch, genesis t, t, n; then the member count.
        let fixed = &v[at..at + 24];
        at += 24;
        let mut indices = Vec::new();
        for _ in 0..3 {
            indices.push(&v[at..at + 2]);
            at = skip_lp(at + 2);
        }
        let mut out = vec![1];
        put(&mut out, network.to_string().as_bytes());
        put(&mut out, network.owner_did().as_bytes());
        out.extend_from_slice(fixed);
        for (index, member) in indices.into_iter().zip(members) {
            out.extend_from_slice(index);
            put(&mut out, member.as_bytes());
        }
        out.extend_from_slice(&v[at..]);
        CertificateBody::decode(&out).unwrap()
    }

    /// The owner's activation of `body`; `holders` sign the readiness
    /// receipts in member order.
    fn activation(body: &CertificateBody, owner: &Keypair, holders: [&Keypair; 3]) -> Vec<u8> {
        let receipts: Vec<ReadinessReceipt> = body
            .members()
            .iter()
            .zip(holders)
            .map(|(member, holder)| ReadinessReceipt {
                index: member.index,
                signature: holder
                    .sign(&readiness_preimage(body, member.index).unwrap())
                    .unwrap(),
            })
            .collect();
        let bytes = activation_preimage(body, &receipts).unwrap();
        let signature = owner.sign(&bytes).unwrap();
        encode_activation(&ActivationObject {
            certificate: body.digest().as_bytes()[..].try_into().unwrap(),
            receipts,
            activation: SignedStatement { bytes, signature },
        })
    }

    #[rocket::async_test]
    async fn a_held_object_is_acknowledged_with_a_signature_that_verifies() {
        let client = client().await;
        // `client()`'s node identity.
        let node = keypair(0x44);
        let (owner, second, third) = (keypair(0x51), keypair(0x52), keypair(0x53));
        let network = NetworkId::new(did(&owner), "vault".to_string()).unwrap();
        let urn = network.to_string();
        let body = genesis(&network, [&did(&node), &did(&second), &did(&third)]);
        let cert = encode_cert(&SignedCertificate {
            body: body.clone(),
            owner_signature: owner.sign(&body.owner_statement()).unwrap(),
        });
        let activation = activation(&body, &owner, [&node, &second, &third]);
        let object = |bytes: &[u8]| encode_config(bytes, URL_SAFE_NO_PAD);

        // An activation before its certificate.
        let (status, text) = push_to(
            &client,
            &urn,
            json!({"kind": "activation", "object": object(&activation), "nonce": "n-1"}),
        )
        .await;
        assert_eq!(status, Status::Conflict);
        assert!(text.contains("threshold_object_unavailable"), "{text}");

        // A certificate that does not name this node.
        let others = genesis(
            &network,
            [&did(&second), &did(&third), &did(&keypair(0x54))],
        );
        let foreign = encode_cert(&SignedCertificate {
            body: others.clone(),
            owner_signature: owner.sign(&others.owner_statement()).unwrap(),
        });
        let (status, text) = push_to(
            &client,
            &urn,
            json!({"kind": "cert", "object": object(&foreign), "nonce": "n-1"}),
        )
        .await;
        assert_eq!(status, Status::Conflict);
        assert!(
            text.contains("threshold_object_unavailable: not_a_member"),
            "{text}"
        );

        let (status, text) = push_to(
            &client,
            &urn,
            json!({"kind": "cert", "object": object(&cert), "nonce": "n-2"}),
        )
        .await;
        assert_eq!(status, Status::Ok, "{text}");
        let ack: Value = serde_json::from_str(&text).unwrap();
        let cid = object_cid(&cert);
        assert_eq!(
            (&ack["network"], &ack["nonce"], &ack["cid"], &ack["node"]),
            (&json!(urn), &json!("n-2"), &json!(cid), &json!(did(&node)))
        );
        assert_eq!(ack["key"], Value::Null);
        let outcome = ack["outcome"].as_str().unwrap();
        let signature = decode_config(ack["signature"].as_str().unwrap(), URL_SAFE_NO_PAD).unwrap();
        assert!(node
            .public()
            .verify(&ack_preimage(&urn, "n-2", &cid, outcome, None), &signature));
        assert!(!node
            .public()
            .verify(&ack_preimage(&urn, "n-1", &cid, outcome, None), &signature));

        let (status, text) = push_to(
            &client,
            &urn,
            json!({"kind": "activation", "object": object(&activation), "nonce": "n-3"}),
        )
        .await;
        assert_eq!(status, Status::Ok, "{text}");
        let chain: Value = client
            .get(format!("/threshold/{urn}/chain"))
            .remote("127.0.0.1:9000".parse().unwrap())
            .dispatch()
            .await
            .into_json()
            .await
            .unwrap();
        let kinds: Vec<&str> = chain["objects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["kind"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, ["cert", "activation"]);
    }
}
