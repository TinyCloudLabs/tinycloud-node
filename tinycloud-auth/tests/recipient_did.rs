use std::{collections::BTreeMap, str::FromStr};

use base64::{engine::general_purpose::URL_SAFE, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use tinycloud_auth::{
    ipld_core::cid::Cid,
    multihash_codetable::{Code, MultihashDigest},
    recipient_did::{
        verify_recipient_did_delegation_bundle_v2, CacaoDelegationArtifactV2, DelegationArtifactV2,
        RecipientDidDelegationBundleV2, UcanDelegationArtifactV2, UcanKind,
    },
    resource::iri_string::types::UriString,
    siwe_recap::Ability,
    ssi::{
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};

const FIXTURE: &str = include_str!("fixtures/recipient-did-v2.json");
const FIXTURE_TIME: u64 = 1_861_920_000;

fn fixture() -> serde_json::Value {
    serde_json::from_str(FIXTURE).expect("approved Stage-0 recipient-DID fixture")
}

fn fixture_bundle() -> RecipientDidDelegationBundleV2 {
    serde_json::from_value(fixture()["bundle"].clone()).expect("fixture bundle")
}

fn key_material(seed: [u8; 32]) -> (JWK, String, String) {
    let signing_key = SigningKey::from_bytes(&seed);
    let public = signing_key.verifying_key();
    let mut multicodec = vec![0xed, 0x01];
    multicodec.extend_from_slice(public.as_bytes());
    let identifier = multibase::encode(multibase::Base::Base58Btc, multicodec);
    let did = format!("did:key:{identifier}");
    let verification_method = format!("{did}#{identifier}");
    let jwk = serde_json::from_value(json!({
        "alg": "EdDSA",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(public.as_bytes()),
        "d": URL_SAFE_NO_PAD.encode(seed),
    }))
    .expect("test Ed25519 JWK");
    (jwk, did, verification_method)
}

fn fixture_session_key() -> (JWK, String, String) {
    let seed: [u8; 32] = URL_SAFE_NO_PAD
        .decode("WfeGHxh9kdePavqU9KOk2vBhGo8LminMpbvERmrKqTw")
        .expect("fixture seed")
        .try_into()
        .expect("32-byte fixture seed");
    key_material(seed)
}

#[derive(Clone)]
struct GrantSpec<'a> {
    issuer_vm: &'a str,
    audience: &'a str,
    proof: Vec<Cid>,
    resource: &'a str,
    actions: Vec<&'a str>,
    caveat: Option<(&'a str, Value)>,
    not_before: Option<f64>,
    expiry: f64,
    mode: Option<&'a str>,
}

fn signed_ucan(jwk: &JWK, spec: GrantSpec<'_>) -> UcanDelegationArtifactV2 {
    let mut attenuation = Capabilities::<Value>::new();
    let mut note_bene = BTreeMap::new();
    if let Some((key, value)) = spec.caveat {
        note_bene.insert(key.to_owned(), value);
    }
    let caveats = if note_bene.is_empty() {
        Vec::<BTreeMap<String, Value>>::new()
    } else {
        vec![note_bene]
    };
    attenuation.with_actions(
        UriString::from_str(spec.resource).expect("test resource"),
        spec.actions.into_iter().map(|action| {
            (
                Ability::from_str(action).expect("test action"),
                caveats.clone(),
            )
        }),
    );
    let facts = spec.mode.map(|mode| {
        vec![json!({
            "xyz.tinycloud.policy/delegationMode": mode,
        })]
    });
    let ucan = Payload {
        issuer: DIDURLBuf::from_str(spec.issuer_vm).expect("issuer DID URL"),
        audience: DIDBuf::from_str(spec.audience).expect("audience DID"),
        not_before: spec
            .not_before
            .map(NumericDate::try_from_seconds)
            .transpose()
            .expect("not-before"),
        expiration: NumericDate::try_from_seconds(spec.expiry).expect("expiry"),
        nonce: Some("urn:uuid:00000000-0000-4000-8000-000000000224".to_owned()),
        facts,
        proof: spec.proof,
        attenuation,
    }
    .sign(Algorithm::EdDSA, jwk)
    .expect("sign test UCAN");
    let value = ucan.encode().expect("encode test UCAN");
    let cid = Cid::new_v1(0x55, Code::Blake3_256.digest(value.as_bytes()));
    UcanDelegationArtifactV2 {
        kind: UcanKind::Ucan,
        cid: cid.to_string(),
        encoding: tinycloud_auth::recipient_did::UcanEncoding::Jwt,
        value,
    }
}

fn fixture_root(bundle: &RecipientDidDelegationBundleV2) -> CacaoDelegationArtifactV2 {
    match bundle.issuer_proofs[0].clone() {
        DelegationArtifactV2::Cacao(root) => root,
        DelegationArtifactV2::Ucan(_) => panic!("fixture root is not Cacao"),
    }
}

fn root_cid(bundle: &RecipientDidDelegationBundleV2) -> Cid {
    Cid::from_str(&fixture_root(bundle).cid).expect("fixture root CID")
}

const RESOURCE: &str =
    "tinycloud:pkh:eip155:1:0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A:default/kv/path";
const OTHER_OWNER_RESOURCE: &str =
    "tinycloud:pkh:eip155:1:0xde709f2102306220921060314715629080e2fb77:default/kv/path";
const RECIPIENT: &str = "did:pkh:eip155:1:0xde709f2102306220921060314715629080e2fb77";
const GRANT_EXPIRY: f64 = 4_000_000_000.0;

fn genuine_intermediate_bundle(
    intermediate_expiry: f64,
    intermediate_mode: Option<&str>,
    grant_parent_is_intermediate: bool,
) -> (RecipientDidDelegationBundleV2, String) {
    let mut bundle = fixture_bundle();
    let (session_one_jwk, _, session_one_vm) = fixture_session_key();
    let (session_two_jwk, session_two_did, session_two_vm) = key_material([0x22; 32]);
    let root = root_cid(&bundle);
    let intermediate = signed_ucan(
        &session_one_jwk,
        GrantSpec {
            issuer_vm: &session_one_vm,
            audience: &session_two_did,
            proof: vec![root],
            resource: RESOURCE,
            actions: vec!["tinycloud.kv/get"],
            caveat: None,
            not_before: Some(1_800_000_000.0),
            expiry: intermediate_expiry,
            mode: intermediate_mode,
        },
    );
    let intermediate_cid = Cid::from_str(&intermediate.cid).expect("intermediate CID");
    bundle
        .issuer_proofs
        .push(DelegationArtifactV2::Ucan(intermediate));
    bundle.grant = signed_ucan(
        &session_two_jwk,
        GrantSpec {
            issuer_vm: &session_two_vm,
            audience: RECIPIENT,
            proof: vec![if grant_parent_is_intermediate {
                intermediate_cid
            } else {
                root
            }],
            resource: RESOURCE,
            actions: vec!["tinycloud.kv/get"],
            caveat: None,
            not_before: Some(1_850_000_000.0),
            expiry: GRANT_EXPIRY,
            mode: Some("terminal"),
        },
    );
    (bundle, session_two_did)
}

#[test]
fn verifies_approved_genuine_sdk_vector_atomically() {
    let vector = fixture();
    let bundle = fixture_bundle();
    let verified = verify_recipient_did_delegation_bundle_v2(bundle, FIXTURE_TIME)
        .expect("genuine owner -> session -> recipient authority");

    assert_eq!(
        serde_json::to_value(verified).expect("native output JSON"),
        vector["nativeVerified"]
    );
}

#[test]
fn verifies_genuine_intermediate_ucan_chain() {
    let (_, session_one_did, _) = fixture_session_key();
    assert_eq!(
        session_one_did,
        "did:key:z6MkmYjTZ8vGCj1aBbe4wxxo3ZgQ8SpCTW6jqRK3dnatDWjM"
    );
    let (bundle, session_two_did) =
        genuine_intermediate_bundle(4_100_000_000.0, Some("attenuable"), true);

    let verified = verify_recipient_did_delegation_bundle_v2(bundle, FIXTURE_TIME)
        .expect("genuine intermediate authority chain");
    assert_eq!(verified.session_principal_did, session_two_did);
    assert_eq!(verified.proof_cids.len(), 2);
    assert_eq!(
        verified.not_before.as_deref(),
        Some("2028-08-16T00:53:20.000Z")
    );
}

#[test]
fn rejects_forged_cacao_even_when_cid_and_grant_parent_are_recomputed() {
    let mut bundle = fixture_bundle();
    let mut root = fixture_root(&bundle);
    let mut bytes = URL_SAFE.decode(&root.value).expect("root bytes");
    let (session_jwk, _, session_vm) = fixture_session_key();
    let cacao: tinycloud_auth::cacaos::siwe_cacao::SiweCacao =
        serde_ipld_dagcbor::from_slice(&bytes).expect("fixture Cacao");
    let signature = cacao.signature().as_ref();
    let offset = bytes
        .windows(signature.len())
        .position(|window| window == signature)
        .expect("signature bytes in DAG-CBOR");
    bytes[offset] ^= 0x01;
    root.value = URL_SAFE.encode(&bytes);
    root.cid = Cid::new_v1(0x55, Code::Blake3_256.digest(&bytes)).to_string();
    let forged_root_cid = Cid::from_str(&root.cid).expect("forged root CID");
    bundle.issuer_proofs = vec![DelegationArtifactV2::Cacao(root)];
    bundle.grant = signed_ucan(
        &session_jwk,
        GrantSpec {
            issuer_vm: &session_vm,
            audience: RECIPIENT,
            proof: vec![forged_root_cid],
            resource: RESOURCE,
            actions: vec!["tinycloud.kv/get"],
            caveat: None,
            not_before: None,
            expiry: GRANT_EXPIRY,
            mode: None,
        },
    );

    let error = verify_recipient_did_delegation_bundle_v2(bundle, FIXTURE_TIME)
        .expect_err("forged Cacao must fail");
    assert!(error.to_string().contains("EIP-191 signature"));
}

#[test]
fn rejects_legacy_one_byte_ed25519_did_key_multicodec() {
    let mut bundle = fixture_bundle();
    let (jwk, _, _) = fixture_session_key();
    let public = jwk.to_public();
    let x = match &public.params {
        tinycloud_auth::ssi::jwk::Params::OKP(params) => params.public_key.0.clone(),
        _ => panic!("fixture is Ed25519"),
    };
    let mut legacy = vec![0xed];
    legacy.extend_from_slice(&x);
    let identifier = multibase::encode(multibase::Base::Base58Btc, legacy);
    let legacy_did = format!("did:key:{identifier}");
    let legacy_vm = format!("{legacy_did}#{identifier}");
    bundle.grant = signed_ucan(
        &jwk,
        GrantSpec {
            issuer_vm: &legacy_vm,
            audience: RECIPIENT,
            proof: vec![root_cid(&bundle)],
            resource: RESOURCE,
            actions: vec!["tinycloud.kv/get"],
            caveat: None,
            not_before: None,
            expiry: GRANT_EXPIRY,
            mode: None,
        },
    );
    assert!(verify_recipient_did_delegation_bundle_v2(bundle, FIXTURE_TIME).is_err());
}

#[test]
fn rejects_zip215_weak_identity_key_before_authority_use() {
    let mut bytes = vec![0xed, 0x01, 0x01];
    bytes.resize(34, 0);
    let identifier = multibase::encode(multibase::Base::Base58Btc, bytes);
    let did = format!("did:key:{identifier}");
    let vm = format!("{did}#{identifier}");
    let payload = URL_SAFE_NO_PAD.encode(
        json!({
            "iss": vm,
            "aud": RECIPIENT,
            "exp": GRANT_EXPIRY as u64,
            "prf": [fixture_root(&fixture_bundle()).cid],
            "att": { RESOURCE: { "tinycloud.kv/get": [{}] } }
        })
        .to_string(),
    );
    let header = URL_SAFE_NO_PAD.encode(
        json!({
            "alg": "EdDSA", "typ": "JWT", "ucv": "0.10.0",
            "jwk": { "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode([1u8].into_iter().chain([0u8; 31]).collect::<Vec<_>>()) }
        })
        .to_string(),
    );
    let mut signature = vec![0u8; 64];
    signature[0] = 1;
    let value = format!("{header}.{payload}.{}", URL_SAFE_NO_PAD.encode(signature));
    let mut bundle = fixture_bundle();
    bundle.grant.value = value.clone();
    bundle.grant.cid = Cid::new_v1(0x55, Code::Blake3_256.digest(value.as_bytes())).to_string();
    assert!(verify_recipient_did_delegation_bundle_v2(bundle, FIXTURE_TIME).is_err());
}

#[test]
fn rejects_exact_mixed_torsion_did_key_before_authority_use() {
    let mixed_point = ED25519_BASEPOINT_POINT + EIGHT_TORSION[1];
    assert!(!mixed_point.is_small_order());
    assert!(!mixed_point.is_torsion_free());
    let mixed_key = mixed_point.compress().to_bytes();
    let mut multicodec = vec![0xed, 0x01];
    multicodec.extend_from_slice(&mixed_key);
    let identifier = multibase::encode(multibase::Base::Base58Btc, multicodec);
    let did = format!("did:key:{identifier}");
    assert_eq!(
        did,
        "did:key:z6MkphrCasciPgfGmTa95e84sY8iXoeTQ645pEFf49nPdZm2"
    );
    let vm = format!("{did}#{identifier}");
    let payload = URL_SAFE_NO_PAD.encode(
        json!({
            "iss": vm,
            "aud": RECIPIENT,
            "exp": GRANT_EXPIRY as u64,
            "prf": [fixture_root(&fixture_bundle()).cid],
            "att": { RESOURCE: { "tinycloud.kv/get": [{}] } }
        })
        .to_string(),
    );
    let header = URL_SAFE_NO_PAD.encode(
        json!({
            "alg": "EdDSA", "typ": "JWT", "ucv": "0.10.0",
            "jwk": { "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(mixed_key) }
        })
        .to_string(),
    );
    let value = format!("{header}.{payload}.{}", URL_SAFE_NO_PAD.encode([0_u8; 64]));
    let mut bundle = fixture_bundle();
    bundle.grant.value = value.clone();
    bundle.grant.cid = Cid::new_v1(0x55, Code::Blake3_256.digest(value.as_bytes())).to_string();

    let error = verify_recipient_did_delegation_bundle_v2(bundle, FIXTURE_TIME)
        .expect_err("mixed-torsion did:key must fail before signature use");
    assert!(error.to_string().contains("torsion-free"));
}

#[test]
fn rejects_invalid_ucan_signature_after_recomputing_its_cid() {
    let mut bundle = fixture_bundle();
    let mut segments: Vec<String> = bundle.grant.value.split('.').map(str::to_owned).collect();
    let mut signature = URL_SAFE_NO_PAD
        .decode(&segments[2])
        .expect("fixture UCAN signature");
    signature[0] ^= 0x01;
    segments[2] = URL_SAFE_NO_PAD.encode(signature);
    let value = segments.join(".");
    bundle.grant.value = value.clone();
    bundle.grant.cid = Cid::new_v1(0x55, Code::Blake3_256.digest(value.as_bytes())).to_string();

    let error = verify_recipient_did_delegation_bundle_v2(bundle, FIXTURE_TIME)
        .expect_err("invalid UCAN signature must fail even with its recomputed CID");
    assert!(error.to_string().contains("Ed25519 signature"));
}

#[test]
fn rejects_action_path_and_caveat_broadening() {
    let (jwk, _, vm) = fixture_session_key();
    for (resource, actions, caveat) in [
        (RESOURCE, vec!["tinycloud.kv/delete"], None),
        (
            "tinycloud:pkh:eip155:1:0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A:default/kv/other",
            vec!["tinycloud.kv/get"],
            None,
        ),
        (
            RESOURCE,
            vec!["tinycloud.kv/get"],
            Some(("limit", json!(1))),
        ),
    ] {
        let mut bundle = fixture_bundle();
        bundle.grant = signed_ucan(
            &jwk,
            GrantSpec {
                issuer_vm: &vm,
                audience: RECIPIENT,
                proof: vec![root_cid(&bundle)],
                resource,
                actions,
                caveat,
                not_before: None,
                expiry: GRANT_EXPIRY,
                mode: None,
            },
        );
        assert!(
            verify_recipient_did_delegation_bundle_v2(bundle, FIXTURE_TIME).is_err(),
            "broadened child must fail"
        );
    }
}

#[test]
fn rejects_expired_and_parent_time_broadening() {
    let (jwk, _, vm) = fixture_session_key();
    let mut expired = fixture_bundle();
    expired.grant = signed_ucan(
        &jwk,
        GrantSpec {
            issuer_vm: &vm,
            audience: RECIPIENT,
            proof: vec![root_cid(&expired)],
            resource: RESOURCE,
            actions: vec!["tinycloud.kv/get"],
            caveat: None,
            not_before: None,
            expiry: FIXTURE_TIME as f64 - 1.0,
            mode: None,
        },
    );
    assert!(verify_recipient_did_delegation_bundle_v2(expired, FIXTURE_TIME).is_err());

    let (broadened, _) = genuine_intermediate_bundle(3_900_000_000.0, Some("attenuable"), true);
    let error = verify_recipient_did_delegation_bundle_v2(broadened, FIXTURE_TIME)
        .expect_err("grant expiry must not exceed intermediate expiry");
    assert!(error.to_string().contains("expiry broadens"));
}

#[test]
fn rejects_expiry_at_the_verification_instant_for_every_artifact_kind() {
    let (jwk, _, vm) = fixture_session_key();
    let mut grant_at_expiry = fixture_bundle();
    grant_at_expiry.grant = signed_ucan(
        &jwk,
        GrantSpec {
            issuer_vm: &vm,
            audience: RECIPIENT,
            proof: vec![root_cid(&grant_at_expiry)],
            resource: RESOURCE,
            actions: vec!["tinycloud.kv/get"],
            caveat: None,
            not_before: None,
            expiry: FIXTURE_TIME as f64,
            mode: None,
        },
    );
    assert!(verify_recipient_did_delegation_bundle_v2(grant_at_expiry, FIXTURE_TIME).is_err());

    let (intermediate_at_expiry, _) =
        genuine_intermediate_bundle(FIXTURE_TIME as f64, Some("attenuable"), true);
    assert!(
        verify_recipient_did_delegation_bundle_v2(intermediate_at_expiry, FIXTURE_TIME).is_err()
    );

    let root_at_expiry =
        verify_recipient_did_delegation_bundle_v2(fixture_bundle(), 32_503_680_000)
            .expect_err("Cacao expiry must be exclusive");
    assert!(root_at_expiry.to_string().contains("owner Cacao"));
}

#[test]
fn rejects_zero_width_ucan_validity_interval() {
    let (jwk, _, vm) = fixture_session_key();
    let mut bundle = fixture_bundle();
    let instant = FIXTURE_TIME as f64 + 10.0;
    bundle.grant = signed_ucan(
        &jwk,
        GrantSpec {
            issuer_vm: &vm,
            audience: RECIPIENT,
            proof: vec![root_cid(&bundle)],
            resource: RESOURCE,
            actions: vec!["tinycloud.kv/get"],
            caveat: None,
            not_before: Some(instant),
            expiry: instant,
            mode: None,
        },
    );

    let error = verify_recipient_did_delegation_bundle_v2(bundle, FIXTURE_TIME)
        .expect_err("zero-width interval can never be valid");
    assert!(error.to_string().contains("inconsistent temporal bounds"));
}

#[test]
fn rejects_space_not_owned_by_cacao_signer() {
    let (jwk, _, vm) = fixture_session_key();
    let mut bundle = fixture_bundle();
    bundle.grant = signed_ucan(
        &jwk,
        GrantSpec {
            issuer_vm: &vm,
            audience: RECIPIENT,
            proof: vec![root_cid(&bundle)],
            resource: OTHER_OWNER_RESOURCE,
            actions: vec!["tinycloud.kv/get"],
            caveat: None,
            not_before: None,
            expiry: GRANT_EXPIRY,
            mode: None,
        },
    );
    assert!(verify_recipient_did_delegation_bundle_v2(bundle, FIXTURE_TIME).is_err());
}

#[test]
fn rejects_terminal_intermediate_and_incomplete_parent_membership() {
    let (terminal, _) = genuine_intermediate_bundle(4_100_000_000.0, Some("terminal"), true);
    let error = verify_recipient_did_delegation_bundle_v2(terminal, FIXTURE_TIME)
        .expect_err("terminal intermediate cannot authorize grant");
    assert!(error.to_string().contains("terminal delegation"));

    let (wrong_parent, _) = genuine_intermediate_bundle(4_100_000_000.0, Some("attenuable"), false);
    let error = verify_recipient_did_delegation_bundle_v2(wrong_parent, FIXTURE_TIME)
        .expect_err("grant must cite transported intermediate directly");
    assert!(error.to_string().contains("preceding transported parent"));
}

#[test]
fn rejects_reordered_duplicate_and_extra_proofs() {
    let (mut reordered, _) = genuine_intermediate_bundle(4_100_000_000.0, Some("attenuable"), true);
    reordered.issuer_proofs.swap(0, 1);
    assert!(verify_recipient_did_delegation_bundle_v2(reordered, FIXTURE_TIME).is_err());

    let mut duplicate = fixture_bundle();
    duplicate
        .issuer_proofs
        .push(DelegationArtifactV2::Cacao(fixture_root(&duplicate)));
    assert!(verify_recipient_did_delegation_bundle_v2(duplicate, FIXTURE_TIME).is_err());

    let (mut extra, _) = genuine_intermediate_bundle(4_100_000_000.0, Some("attenuable"), true);
    let grant_as_proof = DelegationArtifactV2::Ucan(extra.grant.clone());
    extra.issuer_proofs.push(grant_as_proof);
    assert!(verify_recipient_did_delegation_bundle_v2(extra, FIXTURE_TIME).is_err());
}
