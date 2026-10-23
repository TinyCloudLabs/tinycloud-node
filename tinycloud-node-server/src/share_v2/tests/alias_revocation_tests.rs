use super::*;
use k256::ecdsa::SigningKey;
use sha3::Keccak256;
use std::str::FromStr;
use tinycloud_auth::{
    authorization::{EncodingError, HeaderEncode, TinyCloudRevocation},
    cacaos::{
        siwe::{encode_eip55, Message},
        siwe_cacao::{Eip191, Payload, Signature},
    },
    siwe_recap::Capability,
};
use tinycloud_core::{
    events::{Delegation, Revocation},
    util::DelegationInfo,
};

// Public historical-wire ingestion preserves the signed 0/1 recovery byte.
// This is not evidence of a retained credentials database or a full HTTP flow.
struct HistoricalWire(TinyCloudDelegation);

impl HeaderEncode for HistoricalWire {
    fn encode(&self) -> Result<String, EncodingError> {
        self.0.encode()
    }

    fn decode(value: &str) -> Result<(Self, Vec<u8>), EncodingError> {
        let bytes = decode_config(value, base64::URL_SAFE).expect("fixture header encoding");
        Ok((Self(TinyCloudDelegation::from_bytes(&bytes)?), bytes))
    }
}

impl TryFrom<HistoricalWire> for DelegationInfo {
    type Error = <DelegationInfo as TryFrom<TinyCloudDelegation>>::Error;

    fn try_from(value: HistoricalWire) -> Result<Self, Self::Error> {
        Self::try_from(value.0)
    }
}

fn message(address: &[u8; 20], audience: &str, nonce: &str, expiry: OffsetDateTime) -> Message {
    Message::from_str(&format!(
        "localhost wants you to sign in with your Ethereum account:\n0x{}\n\n\nURI: {}\nVersion: 1\nChain ID: 1\nNonce: {}\nIssued At: {}\nExpiration Time: {}",
        encode_eip55(address), audience, nonce,
        timestamp(OffsetDateTime::now_utc() - Duration::minutes(1)), timestamp(expiry)
    )).expect("valid SIWE fixture")
}

fn signed(key: &SigningKey, message: Message, historical: bool) -> Vec<u8> {
    let (signature, recovery) = key
        .sign_prehash_recoverable(&message.eip191_hash().unwrap())
        .unwrap();
    let mut bytes = [0u8; 65];
    bytes[..64].copy_from_slice(&signature.to_bytes());
    bytes[64] = recovery.to_byte() + if historical { 0 } else { 27 };
    let cacao = Payload::from(message).sign::<Eip191>(Signature::from(bytes));
    decode_config(
        TinyCloudDelegation::Cacao(Box::new(cacao))
            .encode()
            .unwrap(),
        base64::URL_SAFE,
    )
    .unwrap()
}

async fn assert_consumers(
    runtime: &ShareV2Runtime,
    policy: &PolicyDocument,
    bytes: &[u8],
    revoked: bool,
) {
    let cid = raw_blake3_cid(bytes);
    let input = OwnerDelegationInput {
        cid: cid.clone(),
        dag_cbor: encode_config(bytes, URL_SAFE_NO_PAD),
    };
    assert_eq!(
        verify_owner_delegation(runtime, policy, &input)
            .await
            .is_err(),
        revoked,
        "actual owner verifier must agree with effective alias revocation"
    );
    assert_eq!(cid_revoked(&runtime.conn, &cid).await.unwrap(), revoked);
    assert_eq!(
        revocation_in_ancestry(&runtime.conn, hash(bytes))
            .await
            .unwrap(),
        revoked
    );
}

async fn signed_alias_consumers(reverse: bool) {
    let secret = StaticSecret::new(vec![0x42; 32]).unwrap();
    let runtime =
        compose_test_runtime(&secret, Some(TeeContext::derive_local(&secret)), true).await;
    let key = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let address: [u8; 20] = Keccak256::digest(&point.as_bytes()[1..])[12..]
        .try_into()
        .unwrap();
    let (_, share_did) = tamper_keypair_and_did();
    let owner = format!("did:pkh:eip155:1:0x{}", encode_eip55(&address));
    let space = format!(
        "tinycloud:pkh:eip155:1:0x{}:default",
        encode_eip55(&address)
    );
    let expiry = OffsetDateTime::now_utc() + Duration::hours(1);
    let mut caps = Capability::<()>::default();
    caps.with_actions_convert(
        format!("{space}/kv/shares/alias/document.md"),
        [("tinycloud.kv/get", [])],
    )
    .unwrap();
    let grant = caps
        .build_message(message(&address, &share_did, "sharealias1071", expiry))
        .unwrap();
    let historical = signed(&key, grant.clone(), true);
    let canonical = signed(&key, grant, false);
    let unrelated = signed(
        &key,
        caps.build_message(message(&address, &share_did, "unrelated1071", expiry))
            .unwrap(),
        false,
    );
    assert_ne!(hash(&historical), hash(&canonical));
    for bytes in [&historical, &canonical, &unrelated] {
        let parsed = TinyCloudDelegation::from_bytes(bytes).unwrap();
        verify_delegation_signature(&parsed).await.unwrap();
        let event =
            Delegation::from_header_ser::<HistoricalWire>(&encode_config(bytes, base64::URL_SAFE))
                .unwrap();
        runtime
            .tinycloud
            .delegate(event)
            .await
            .map_err(|error| error.to_string())
            .unwrap();
        let row = delegation::Entity::find_by_id(hash(bytes))
            .one(&runtime.conn)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            maybe_decrypt(Some(&runtime.policy_encryption), &row.serialization).unwrap(),
            *bytes,
            "stored content and its hash must retain the actual signed wire bytes"
        );
    }
    let (mut envelope, _, _) = sample_policy();
    envelope.policy.owner_did = owner;
    envelope.policy.share_key_did = share_did;
    envelope.policy.target.space_id = space;
    envelope.policy.resource.path = "shares/alias/document.md".into();
    envelope.policy.actions = vec!["tinycloud.kv/get".into()];
    envelope.policy.expires_at = timestamp(expiry - Duration::minutes(1));
    for bytes in [&historical, &canonical, &unrelated] {
        assert_consumers(&runtime, &envelope.policy, bytes, false).await;
    }
    let target = if reverse { &canonical } else { &historical };
    let revocation_bytes = signed(
        &key,
        message(
            &address,
            &format!("ucan:{}", raw_blake3_cid(target)),
            "revokeshare1071",
            expiry,
        ),
        false,
    );
    let event = Revocation::from_header_ser::<TinyCloudRevocation>(&encode_config(
        revocation_bytes,
        base64::URL_SAFE,
    ))
    .unwrap();
    runtime
        .tinycloud
        .revoke(event)
        .await
        .map_err(|error| error.to_string())
        .unwrap();
    for bytes in [&historical, &canonical] {
        assert_consumers(&runtime, &envelope.policy, bytes, true).await;
    }
    assert_consumers(&runtime, &envelope.policy, &unrelated, false).await;
}

#[tokio::test]
async fn signed_legacy_revocation_denies_canonical_share_owner_consumers() {
    signed_alias_consumers(false).await;
}

#[tokio::test]
async fn signed_canonical_revocation_denies_legacy_share_owner_consumers() {
    signed_alias_consumers(true).await;
}
