//! TC-1071: changing only the CACAO issuer's address casing must not resurrect
//! a revoked, valid SIWE grant. All requests use throwaway keys and the real app.
use std::collections::HashMap;

use anyhow::{ensure, Result};
use k256::ecdsa::SigningKey;
use rocket::{
    figment::providers::Serialized,
    http::{ContentType, Header, Status},
    local::asynchronous::{Client, LocalRequest},
};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use tinycloud_auth::{
    authorization::{
        make_invocation_from_uris, Cid, HeaderEncode, InvocationOptions, TinyCloudDelegation,
        TinyCloudRevocation,
    },
    cacaos::{
        siwe::{encode_eip55, Message},
        siwe_cacao::Signature,
    },
    ipld_core::ipld::Ipld,
    resource::{Path, Service, SpaceId},
};
use tinycloud_sdk_wasm::{
    host::{generate_host_siwe_message, siwe_to_delegation_headers, HostConfig, SignedMessage},
    session::{complete_session_setup, prepare_session, Session, SessionConfig, SignedSession},
};

struct Wallet {
    key: SigningKey,
    address: [u8; 20],
    space: SpaceId,
}

impl Wallet {
    fn new() -> Result<Self> {
        let key = SigningKey::from_bytes(&[37; 32].into())?;
        let public = key.verifying_key().to_encoded_point(false);
        let digest = Keccak256::digest(&public.as_bytes()[1..]);
        let address = digest[12..].try_into()?;
        let did = format!("did:pkh:eip155:1:0x{}", encode_eip55(&address));
        Ok(Self {
            key,
            address,
            space: SpaceId::new(did.parse()?, "issuer-case".parse()?),
        })
    }

    fn sign(&self, message: &Message) -> Result<Signature> {
        let (signature, recovery) = self.key.sign_prehash_recoverable(&message.eip191_hash()?)?;
        let mut bytes = [0; 65];
        bytes[..64].copy_from_slice(signature.to_bytes().as_ref());
        bytes[64] = u8::from(recovery) + 27;
        Ok(Signature::from(bytes))
    }

    fn session(&self) -> Result<Session> {
        let now = time::OffsetDateTime::now_utc();
        let prepared = prepare_session(SessionConfig {
            abilities: HashMap::from([(
                "kv".parse()?,
                HashMap::from([("".parse()?, vec!["tinycloud.kv/list".parse()?])]),
            )]),
            space_abilities: None,
            raw_abilities: HashMap::new(),
            address: self.address,
            chain_id: 1,
            domain: "localhost".parse()?,
            issued_at: now.into(),
            space_id: self.space.clone(),
            additional_spaces: None,
            not_before: None,
            expiration_time: (now + time::Duration::hours(1)).into(),
            parents: None,
            jwk: None,
            delegate_uri: None,
            nonce: None,
            invocation_ttl_secs: None,
        })?;
        let signature = self.sign(&prepared.siwe)?;
        Ok(complete_session_setup(SignedSession {
            session: prepared,
            signature,
        })?)
    }
}

fn authorization(headers: &impl serde::Serialize) -> Result<String> {
    Ok(serde_json::to_value(headers)?["Authorization"]
        .as_str()
        .unwrap()
        .to_owned())
}

fn wire(value: &Ipld) -> Result<String> {
    Ok(base64::encode_config(
        serde_ipld_dagcbor::to_vec(value)?,
        base64::URL_SAFE,
    ))
}

fn wire_value(header: &str) -> Result<Ipld> {
    Ok(serde_ipld_dagcbor::from_slice(&base64::decode_config(
        header,
        base64::URL_SAFE,
    )?)?)
}

fn payload(value: &mut Ipld) -> &mut std::collections::BTreeMap<String, Ipld> {
    let Ipld::Map(cacao) = value else {
        panic!("CACAO map")
    };
    let Ipld::Map(payload) = cacao.get_mut("p").unwrap() else {
        panic!("payload map")
    };
    payload
}

async fn dispatch(request: LocalRequest<'_>) -> (Status, String) {
    let response = request.dispatch().await;
    (
        response.status(),
        response.into_string().await.unwrap_or_default(),
    )
}

async fn expect_ok(label: &str, request: LocalRequest<'_>) -> Result<String> {
    let (status, body) = dispatch(request).await;
    ensure!(status == Status::Ok, "{label}: {status} {body}");
    Ok(body)
}

async fn client() -> Result<(Client, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let mut config = tinycloud::config::Config::default();
    config.storage.datadir = dir.path().into();
    config.storage.database = Some("sqlite::memory:".into());
    config.keys = serde_json::from_value(
        json!({"type":"static", "secret":base64::encode_config([43; 32], base64::URL_SAFE_NO_PAD)}),
    )?;
    let figment = rocket::figment::Figment::from(rocket::Config {
        address: "127.0.0.1".parse()?,
        log_level: rocket::config::LogLevel::Off,
        ..rocket::Config::default()
    })
    .merge(Serialized::defaults(&config));
    let rocket = tinycloud::app_with_control(&figment, &config, None).await?;
    Ok((Client::tracked(rocket).await?, dir))
}

async fn bootstrap(client: &Client, wallet: &Wallet) -> Result<()> {
    let peer = expect_ok(
        "peer",
        client.get(format!("/peer/generate/{}", wallet.space)),
    )
    .await?;
    let message = generate_host_siwe_message(HostConfig {
        address: wallet.address,
        chain_id: 1,
        domain: "localhost".parse()?,
        issued_at: time::OffsetDateTime::now_utc().into(),
        space_id: wallet.space.clone(),
        peer_id: peer,
    })?;
    let signature = wallet.sign(&message)?;
    let header = authorization(&siwe_to_delegation_headers(SignedMessage {
        siwe: message,
        signature,
    }))?;
    expect_ok(
        "host grant",
        client
            .post("/delegate")
            .header(Header::new("Authorization", header)),
    )
    .await?;
    Ok(())
}

fn list_header(session: &Session, cid: Cid) -> Result<String> {
    let mut invocation = session.clone();
    invocation.delegation_cid = cid;
    Ok(invocation
        .invoke(
            [(
                "kv".parse::<Service>()?,
                "".parse::<Path>()?,
                None,
                None,
                ["tinycloud.kv/list".parse()?],
            )],
            None,
        )?
        .encode()?)
}

async fn status(client: &Client, session: &Session, cid: &str) -> Result<Value> {
    let invocation = make_invocation_from_uris(
        [(
            format!("urn:cid:{cid}").parse()?,
            ["tinycloud.delegation/status".parse()?],
        )],
        &cid.parse()?,
        &session.jwk,
        &session.verification_method,
        (time::OffsetDateTime::now_utc() + time::Duration::minutes(5)).unix_timestamp() as f64,
        InvocationOptions {
            proof: Some(vec![]),
            ..InvocationOptions::default()
        },
    )?
    .encode()?;
    let body = expect_ok(
        "status",
        client
            .post("/delegation/status")
            .header(Header::new("Authorization", invocation))
            .header(ContentType::JSON)
            .body(json!({"cid":cid}).to_string()),
    )
    .await?;
    Ok(serde_json::from_str(&body)?)
}

#[tokio::test]
async fn issuer_case_reimport_cannot_resurrect_revoked_siwe_grant() -> Result<()> {
    let (client, _dir) = client().await?;
    let wallet = Wallet::new()?;
    bootstrap(&client, &wallet).await?;
    let session = wallet.session()?;
    let canonical = authorization(&session.delegation_header)?;
    let mut variant = wire_value(&canonical)?;
    let Ipld::String(issuer) = payload(&mut variant).get("iss").unwrap() else {
        panic!("issuer")
    };
    let issuer = issuer.clone();
    let (prefix, address) = issuer.rsplit_once(':').unwrap();
    let lower = format!("{prefix}:{}", address.to_ascii_lowercase());
    assert_ne!(
        issuer, lower,
        "fixture must have a mixed-case EIP55 address"
    );
    payload(&mut variant).insert("iss".into(), Ipld::String(lower));
    let variant = wire(&variant)?;

    // Same signature, same personal_sign bytes; no resigning the alias.
    let (TinyCloudDelegation::Cacao(original), _) = TinyCloudDelegation::decode(&canonical)? else {
        panic!("CACAO")
    };
    let (TinyCloudDelegation::Cacao(alias), _) = TinyCloudDelegation::decode(&variant)? else {
        panic!("CACAO")
    };
    let message: Message = original.payload().clone().try_into()?;
    let alias_message: Message = alias.payload().clone().try_into()?;
    assert_eq!(message.eip191_bytes()?, alias_message.eip191_bytes()?);
    assert_eq!(original.signature(), alias.signature());
    original.verify().await?;
    alias.verify().await?;

    let grant: Value = serde_json::from_str(
        &expect_ok(
            "canonical grant",
            client
                .post("/delegate")
                .header(Header::new("Authorization", canonical)),
        )
        .await?,
    )?;
    let cid = grant["cid"].as_str().unwrap();
    assert_eq!(status(&client, &session, cid).await?["status"], "active");
    let before = expect_ok(
        "signed kv/list before revoke",
        client.post("/invoke").header(Header::new(
            "Authorization",
            list_header(&session, cid.parse()?)?,
        )),
    )
    .await?;
    println!("canonical={cid} status=active signed kv/list=200 body={before}");

    let mut revocation_message = message;
    revocation_message.uri = format!("ucan:{cid}").parse()?;
    revocation_message.statement = None;
    revocation_message.resources.clear();
    let signature = wallet.sign(&revocation_message)?;
    let revocation = TinyCloudRevocation::Cacao(Box::new(
        tinycloud_auth::cacaos::siwe_cacao::Payload::from(revocation_message)
            .sign::<tinycloud_auth::cacaos::siwe_cacao::Eip191>(signature),
    ));
    expect_ok(
        "signed revoke",
        client
            .post("/revoke")
            .header(Header::new("Authorization", revocation.encode()?)),
    )
    .await?;
    assert_eq!(status(&client, &session, cid).await?["status"], "revoked");
    let (revoked_status, revoked_body) = dispatch(client.post("/invoke").header(Header::new(
        "Authorization",
        list_header(&session, cid.parse()?)?,
    )))
    .await;
    assert_eq!(
        revoked_status,
        Status::Unauthorized,
        "canonical after revoke: {revoked_body}"
    );
    assert!(
        revoked_body.contains("delegation-revoked"),
        "{revoked_body}"
    );

    let imported: Value = serde_json::from_str(
        &expect_ok(
            "case-only reimport",
            client
                .post("/delegate")
                .header(Header::new("Authorization", variant)),
        )
        .await?,
    )?;
    let alias_cid = imported["cid"].as_str().unwrap();
    let alias_status = status(&client, &session, alias_cid).await?;
    let (invoke_status, invoke_body) = dispatch(client.post("/invoke").header(Header::new(
        "Authorization",
        list_header(&session, alias_cid.parse()?)?,
    )))
    .await;
    println!(
        "reimport={alias_cid} status={} signed kv/list={invoke_status} body={invoke_body}",
        alias_status["status"]
    );
    assert_eq!(
        invoke_status,
        Status::Unauthorized,
        "case-only revoked grant must not authorize kv/list: {invoke_body}"
    );
    assert!(invoke_body.contains("delegation-revoked"), "{invoke_body}");
    assert_eq!(alias_status["status"], "revoked");
    assert_eq!(alias_status["revoked"], true);
    assert_eq!(
        alias_cid, cid,
        "equivalent signed messages must have one CID"
    );
    Ok(())
}

fn signature_bytes(value: &mut Ipld) -> &mut Vec<u8> {
    let Ipld::Map(cacao) = value else {
        panic!("CACAO map")
    };
    let Ipld::Map(signature) = cacao.get_mut("s").unwrap() else {
        panic!("signature map")
    };
    let Ipld::Bytes(bytes) = signature.get_mut("s").unwrap() else {
        panic!("signature bytes")
    };
    bytes
}

#[tokio::test]
async fn issuer_representations_share_canonical_bytes_without_changing_signed_text() -> Result<()> {
    let wallet = Wallet::new()?;
    let session = wallet.session()?;
    let header = authorization(&session.delegation_header)?;
    let (TinyCloudDelegation::Cacao(original), canonical) = TinyCloudDelegation::decode(&header)?
    else {
        panic!("CACAO")
    };
    let message: Message = original.payload().clone().try_into()?;
    let signed_bytes = message.eip191_bytes()?;
    let canonical_cid = tinycloud_core::hash::hash(&canonical).to_cid(0x55);
    let checksum = encode_eip55(&wallet.address);
    let cases = [
        checksum.to_ascii_lowercase(),
        checksum.to_ascii_uppercase(),
        checksum
            .chars()
            .map(|c| {
                if c.is_ascii_uppercase() {
                    c.to_ascii_lowercase()
                } else {
                    c.to_ascii_uppercase()
                }
            })
            .collect(),
    ];
    for chain in ["1", "0001", "+1"] {
        for address in &cases {
            for recovery_offset in [0, 27] {
                let mut variant = wire_value(&header)?;
                payload(&mut variant).insert(
                    "iss".into(),
                    Ipld::String(format!("did:pkh:eip155:{chain}:0x{address}")),
                );
                signature_bytes(&mut variant)[64] -= recovery_offset;
                let (TinyCloudDelegation::Cacao(alias), bytes) =
                    TinyCloudDelegation::decode(&wire(&variant)?)?
                else {
                    panic!("CACAO")
                };
                let alias_message: Message = alias.payload().clone().try_into()?;
                assert_eq!(
                    alias_message.eip191_bytes()?,
                    signed_bytes,
                    "{chain} {address}"
                );
                alias.verify().await?;
                assert_eq!(alias.signature(), original.signature(), "v normalization");
                assert_eq!(
                    bytes, canonical,
                    "{chain} {address} v-offset={recovery_offset}"
                );
                assert_eq!(
                    tinycloud_core::hash::hash(&bytes).to_cid(0x55),
                    canonical_cid
                );
                assert_eq!(
                    TinyCloudDelegation::Cacao(alias).encode()?,
                    header,
                    "new wire encoding"
                );
            }
        }
    }

    Ok(())
}

#[tokio::test]
async fn issuer_canonicalization_does_not_accept_invalid_signatures_or_changed_signed_fields(
) -> Result<()> {
    let (client, _dir) = client().await?;
    let wallet = Wallet::new()?;
    bootstrap(&client, &wallet).await?;
    let session = wallet.session()?;
    let header = authorization(&session.delegation_header)?;
    let (TinyCloudDelegation::Cacao(original), bytes) = TinyCloudDelegation::decode(&header)?
    else {
        panic!("CACAO")
    };
    let message: Message = original.payload().clone().try_into()?;

    let mutations = [
        ("nonce", Ipld::String("ChangedNonce1071".into())),
        (
            "iss",
            Ipld::String(format!(
                "did:pkh:eip155:2:0x{}",
                encode_eip55(&wallet.address)
            )),
        ),
        (
            "iss",
            Ipld::String("did:pkh:eip155:1:0x1111111111111111111111111111111111111111".into()),
        ),
        ("domain", Ipld::String("other.example".into())),
        (
            "iat",
            Ipld::String(message.issued_at.to_string().replace('Z', "+00:00")),
        ),
        ("aud", Ipld::String("did:key:z6MkiAlternateAudience".into())),
    ];
    for (field, value) in mutations {
        let mut variant = wire_value(&header)?;
        payload(&mut variant).insert(field.into(), value);
        let mutated = wire(&variant)?;
        let (TinyCloudDelegation::Cacao(cacao), _) = TinyCloudDelegation::decode(&mutated)? else {
            panic!("CACAO")
        };
        assert!(
            cacao.verify().await.is_err(),
            "changed {field} must fail signature verification"
        );
        let (status, body) = dispatch(
            client
                .post("/delegate")
                .header(Header::new("Authorization", mutated)),
        )
        .await;
        assert_eq!(status, Status::Unauthorized, "changed {field}: {body}");
    }

    for failure in ["high-s", "zero-r", "zero-s", "invalid-v", "wrong-signer"] {
        let mut variant = wire_value(&header)?;
        let signature = signature_bytes(&mut variant);
        match failure {
            "high-s" => {
                // secp256k1 n-s, with the matching recovery parity toggle.
                let order = hex::decode(
                    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
                )?;
                let mut borrow = 0i16;
                for i in (0..32).rev() {
                    let difference = i16::from(order[i]) - i16::from(signature[32 + i]) - borrow;
                    signature[32 + i] = difference as u8;
                    borrow = i16::from(difference < 0);
                }
                signature[64] = 27 + ((signature[64] - 27) ^ 1);
            }
            "zero-r" => signature[..32].fill(0),
            "zero-s" => signature[32..64].fill(0),
            "invalid-v" => signature[64] = 29,
            "wrong-signer" => signature[0] ^= 1,
            _ => unreachable!(),
        }
        let invalid = wire(&variant)?;
        let decoded = TinyCloudDelegation::decode(&invalid);
        if failure == "wrong-signer" {
            let (TinyCloudDelegation::Cacao(cacao), _) = decoded? else {
                panic!("CACAO")
            };
            assert!(cacao.verify().await.is_err());
        } else {
            assert!(decoded.is_err(), "{failure} must be rejected at decode");
        }
        let (status, body) = dispatch(
            client
                .post("/delegate")
                .header(Header::new("Authorization", invalid)),
        )
        .await;
        assert_eq!(status, Status::Unauthorized, "{failure}: {body}");
    }

    // An independently signed message remains a different grant, not an alias.
    let mut distinct_message = message;
    distinct_message.nonce = "DifferentValidNonce1071".into();
    let signature = wallet.sign(&distinct_message)?;
    let distinct = tinycloud_auth::cacaos::siwe_cacao::Payload::from(distinct_message)
        .sign::<tinycloud_auth::cacaos::siwe_cacao::Eip191>(signature);
    distinct.verify().await?;
    let distinct = TinyCloudDelegation::Cacao(Box::new(distinct)).encode()?;
    let (_, distinct_bytes) = TinyCloudDelegation::decode(&distinct)?;
    assert_ne!(
        tinycloud_core::hash::hash(&distinct_bytes),
        tinycloud_core::hash::hash(&bytes)
    );
    expect_ok(
        "independently signed distinct grant",
        client
            .post("/delegate")
            .header(Header::new("Authorization", distinct)),
    )
    .await?;
    println!(
        "invalid signatures and changed signed fields rejected; distinct signed grant accepted"
    );
    Ok(())
}
