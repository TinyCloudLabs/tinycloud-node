//! Real-time held-credential fixtures for the mint-path tests in
//! `held_route_tests.rs`.
//!
//! The checked-in held vector is pinned to 2026-01-01, so these fixtures build
//! their SD-JWT, SIWE message, and account authorization at the server's
//! current time. The SD-JWT is signed with the harness issuer key that the held
//! issuer config pins. The account authorization follows the v2 `/delegate`
//! flow, and the account owner uses the same fixed secret as that flow.

use super::test_harness::*;
use super::*;
use rocket::http::{ContentType, Status};
use serde_json::{json, Value};
use sha3::Keccak256;
use time::{Duration, OffsetDateTime};
use tinycloud_auth::{
    authorization::HeaderEncode,
    cacaos::{
        siwe::{encode_eip55, Message, Version},
        siwe_cacao::{Header as SiweHeader, Signature as SiweSignature, SiweCacao},
    },
    siwe_recap::{Ability as RecapAbility, Capability as RecapCapability},
};
use tinycloud_core::{models::space, sea_orm::ActiveValue::Set, types::SpaceIdWrap};

const HELD_EMAIL: &str = "alice@example.test";
const HELD_PROFILE: &str = "tinycloud.email-held/v1";
const HELD_VCT: &str = "opencredentials.email/v1";
const HELD_AUDIENCE: &str = "relying-party.example";
const HELD_STATEMENT: &str = "Present a TinyCloud held credential";
const BINDING_DOMAIN: &str = "tinycloud.credentials/account-binding/v1";

/// Secret for the account owner. The v2 flow uses the same key, so the account
/// DID here matches the owner the account authorization is issued for.
const ACCOUNT_SECRET: [u8; 32] = [0x47; 32];

/// Process-unique serial. Nonces and credential `jti` values derive from it, so
/// every presentation a test builds is distinct.
fn serial() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// A SIWE nonce: alphanumeric and at least 22 characters.
pub(super) fn held_nonce() -> String {
    format!("heldnonce{:012}{:08}", std::process::id(), serial())
}

fn held_jti() -> String {
    format!("urn:uuid:00000000-0000-4000-8000-{:012x}", serial())
}

fn b64(bytes: &[u8]) -> String {
    base64::encode_config(bytes, base64::URL_SAFE_NO_PAD)
}

fn disclosure(salt: &str, name: &str, value: &str) -> String {
    b64(json!([salt, name, value]).to_string().as_bytes())
}

/// The account `did:pkh` and its EIP-55 address.
pub(super) struct HeldAccount {
    key: k256::ecdsa::SigningKey,
    address: [u8; 20],
    pub(super) did: String,
}

impl HeldAccount {
    pub(super) fn new() -> anyhow::Result<Self> {
        let key = k256::ecdsa::SigningKey::from_bytes(&ACCOUNT_SECRET.into())?;
        let public = key.verifying_key().to_encoded_point(false);
        let digest = Keccak256::digest(&public.as_bytes()[1..]);
        let address: [u8; 20] = digest[12..].try_into()?;
        let did = format!("did:pkh:eip155:1:0x{}", encode_eip55(&address));
        Ok(Self { key, address, did })
    }

    fn address(&self) -> String {
        format!("0x{}", encode_eip55(&self.address))
    }
}

fn eip191_sign(key: &k256::ecdsa::SigningKey, message: &str) -> anyhow::Result<String> {
    let prefixed = format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message);
    let digest = Keccak256::digest(prefixed.as_bytes());
    let (signature, recovery) = key.sign_prehash_recoverable(&digest)?;
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(recovery.to_byte() + 27);
    Ok(format!("0x{}", hex::encode(bytes)))
}

pub(super) struct HeldPresentation {
    pub(super) sd_jwt: String,
    pub(super) message: String,
    pub(super) signature: String,
}

/// Builds an SD-JWT that discloses only `email`, plus a SIWE message whose
/// `Resources` entry binds the SD-JWT. The credential is valid from one minute
/// before now until `lifetime_seconds` from now.
pub(super) fn held_presentation(
    h: &Harness,
    account: &HeldAccount,
    nonce: &str,
    lifetime_seconds: i64,
) -> anyhow::Result<HeldPresentation> {
    let now_unix = now().unix_timestamp();
    let issued = now_unix - 60;
    let issuer_did = h.vector["policyProjection"]["issuerDid"]
        .as_str()
        .expect("vector issuerDid")
        .to_owned();
    let kid = h.vector["policyProjection"]["issuerKid"].clone();
    let disclosures = vec![disclosure(
        &format!("salt{}", serial()),
        "email",
        HELD_EMAIL,
    )];
    let digests: Vec<String> = disclosures
        .iter()
        .map(|d| b64(&Sha256::digest(d.as_bytes())))
        .collect();
    let header = json!({"alg": "EdDSA", "typ": "vc+sd-jwt", "kid": kid});
    let payload = json!({
        "iss": issuer_did,
        "sub": account.did,
        "iat": issued,
        "nbf": issued,
        "exp": now_unix + lifetime_seconds,
        "jti": held_jti(),
        "vct": HELD_VCT,
        "profile": HELD_PROFILE,
        "profileVersion": 1,
        "holderBinding": {"did": account.did, "signingDomain": BINDING_DOMAIN},
        "status": {"method": "none"},
        "_sd_alg": "sha-256",
        "_sd": digests,
    });
    let signing_input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(payload.to_string().as_bytes())
    );
    let signature = h.issuer.sign(signing_input.as_bytes());
    let mut sd_jwt = format!("{signing_input}.{}~", b64(&signature));
    for disclosure in &disclosures {
        sd_jwt.push_str(disclosure);
        sd_jwt.push('~');
    }
    let message = [
        format!("{HELD_AUDIENCE} wants you to sign in with your Ethereum account:"),
        account.address(),
        String::new(),
        HELD_STATEMENT.to_owned(),
        String::new(),
        format!("URI: https://{HELD_AUDIENCE}"),
        "Version: 1".to_owned(),
        "Chain ID: 1".to_owned(),
        format!("Nonce: {nonce}"),
        format!("Issued At: {}", format_time(now())),
        "Resources:".to_owned(),
        format!(
            "- urn:tinycloud:sd-hash:{}",
            b64(&Sha256::digest(sd_jwt.as_bytes()))
        ),
    ]
    .join("\n");
    let signature = eip191_sign(&account.key, &message)?;
    Ok(HeldPresentation {
        sd_jwt,
        message,
        signature,
    })
}

/// A presentation whose SIWE nonce is recorded as outstanding in the app's own
/// store. The production writer is not wired while the flag is off, so the
/// test writes the row the way a future mint slice would.
pub(super) async fn outstanding_presentation(
    h: &Harness,
    account: &HeldAccount,
    lifetime_seconds: i64,
) -> anyhow::Result<HeldPresentation> {
    let nonce = held_nonce();
    crate::held_email::record_nonce(
        &h.client.rocket().state::<PolicyV3Runtime>().unwrap().conn,
        HELD_AUDIENCE,
        &nonce,
        // The consume check keys on `Pkh::canonical`, which is lowercase.
        &account.did.to_ascii_lowercase(),
        now().unix_timestamp() + 86_400,
    )
    .await?;
    held_presentation(h, account, &nonce, lifetime_seconds)
}

/// Imports the account's SDK session CACAO through `/delegate`, inserts the
/// credentials space row, and returns the stored CID and the space it authorizes.
pub(super) async fn import_account_authorization(
    h: &Harness,
    account: &HeldAccount,
) -> anyhow::Result<(String, String)> {
    let credentials_space = SpaceId::new(account.did.parse::<DIDBuf>()?, "credentials".parse()?);
    let now = OffsetDateTime::now_utc().replace_nanosecond(0)?;
    let issued = now - Duration::seconds(5);
    let expires = now + Duration::seconds(600);
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
        domain: "tinycloud.test".parse()?,
        address: account.address,
        statement: None,
        uri: h.holder.did().parse()?,
        version: Version::V1,
        chain_id: 1,
        nonce: held_nonce(),
        issued_at: issued.into(),
        expiration_time: Some(expires.into()),
        not_before: None,
        request_id: None,
        resources: vec![],
    })?;
    let (signature, recovery_id) = account
        .key
        .sign_prehash_recoverable(&account_message.eip191_hash()?)?;
    let mut signature_bytes = [0_u8; 65];
    signature_bytes[..64].copy_from_slice(signature.to_bytes().as_ref());
    signature_bytes[64] = u8::from(recovery_id) + 27;
    let authorization = TinyCloudDelegation::Cacao(Box::new(SiweCacao::new(
        account_message.into(),
        SiweSignature::from(signature_bytes),
        SiweHeader,
    )))
    .encode()?;
    let response = h
        .client
        .post("/delegate")
        .header(rocket::http::Header::new("Authorization", authorization))
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    anyhow::ensure!(status == Status::Ok, "account /delegate: {status} {body}");
    let account_cid: tinycloud_auth::ipld_core::cid::Cid = serde_json::from_str::<Value>(&body)?
        ["cid"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing account delegation cid"))?
        .parse()?;
    h.client
        .rocket()
        .state::<crate::TinyCloud>()
        .unwrap()
        .load_signed_delegation(account_cid)
        .await
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("missing stored account authorization"))?;
    space::ActiveModel {
        id: Set(SpaceIdWrap(credentials_space.clone())),
    }
    .insert(&h.client.rocket().state::<PolicyV3Runtime>().unwrap().conn)
    .await?;
    Ok((account_cid.to_string(), credentials_space.to_string()))
}

/// The held requirement the policy is registered against and the mint sends.
pub(super) fn held_requirement() -> Value {
    json!({
        "type": "TinyCloudCredentialRequirement",
        "version": 1,
        "profile": {"id": HELD_PROFILE, "version": 1},
        "credentialType": {"id": HELD_VCT, "version": 1},
        "claims": {"email": HELD_EMAIL},
        "maxAgeSeconds": HELD_EMAIL_MAX_AGE_SECONDS,
    })
}

fn held_projection(h: &Harness, requirement: &Value) -> Value {
    json!({
        "type": "TinyCloudPolicyCredentialRequirement",
        "version": 1,
        "requirementDigest": canonical_digest_base64url(requirement),
        "descriptorDigest": h.vector["policyProjection"]["descriptorDigest"],
        "issuerDid": h.vector["policyProjection"]["issuerDid"],
        "issuerKid": h.vector["policyProjection"]["issuerKid"],
        "profile": {"id": HELD_PROFILE, "version": 1},
        "credentialType": {"id": HELD_VCT, "version": 1},
    })
}

/// Registers a policy whose credential requirement is the held requirement.
/// The vector projection cannot be reused: it pins the v3 profile.
pub(super) async fn register_held(h: &Harness) -> anyhow::Result<Registered> {
    let projection = held_projection(h, &held_requirement());
    let (status, body, registered) = h
        .register_with_projection(policy_window(), projection)
        .await?;
    anyhow::ensure!(status == Status::Ok, "register held: {status} {body}");
    Ok(registered)
}

/// Mints through `POST /policy/v3/delegations` with a fresh challenge. The body
/// has no `credential` field, which is the held shape.
pub(super) async fn mint_held(
    h: &Harness,
    policy: &Registered,
    presentation: &HeldPresentation,
    account_cid: &str,
    credential_space: &str,
    requested_expires_at: &str,
) -> anyhow::Result<(Status, String)> {
    let (status, body) = h.challenge(policy).await;
    anyhow::ensure!(status == Status::Ok, "challenge: {status} {body}");
    let challenge: Value = serde_json::from_str(&body)?;
    let response = h
        .client
        .post("/policy/v3/delegations")
        .header(ContentType::JSON)
        .body(
            json!({
                "policyCid": policy.policy_cid,
                "challengeId": challenge["challengeId"],
                "nonce": challenge["nonce"],
                "requirement": held_requirement(),
                "presentation": {
                    "sdJwt": presentation.sd_jwt,
                    "siwe": {
                        "message": presentation.message,
                        "signature": presentation.signature,
                    },
                },
                "accountAuthorizationCid": account_cid,
                "credentialSpaceId": credential_space,
                "requestedExpiresAt": requested_expires_at,
            })
            .to_string(),
        )
        .dispatch()
        .await;
    let status = response.status();
    Ok((status, response.into_string().await.unwrap_or_default()))
}
