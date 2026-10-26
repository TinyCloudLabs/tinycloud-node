//! TC-2132: `POST /delegation/query` with `direction: "issued"`.
//!
//! The agent signs with its own key, one `tinycloud.delegation/list`
//! capability on `<its own DID>/delegation`, no proof; it sees only the rows
//! it is the delegator of.

use super::*;
use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::Client;
use tinycloud_auth::{
    authorization::Cid as AuthCid,
    ssi::{
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        jwk::Algorithm,
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    hash::Hash,
    models::{abilities, actor, delegation},
    sea_orm::{ActiveModelTrait, ActiveValue::Set},
    types::DelegationQuery,
};

/// A did:key that signs queries.
struct Agent {
    jwk: JWK,
    vm: String,
    did: String,
}

impl Agent {
    fn new() -> Result<Self> {
        let mut jwk = JWK::generate_ed25519()?;
        jwk.algorithm = Some(Algorithm::EdDSA);
        let did = DID_METHODS.generate(&jwk, "key")?.to_string();
        let fragment = did
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("missing did:key fragment"))?
            .1
            .to_string();
        Ok(Self {
            vm: format!("{did}#{fragment}"),
            did,
            jwk,
        })
    }

    /// `<did>:agent/delegation`: the resource of the list capability.
    fn list_resource(&self, did: &str) -> Result<Resource> {
        Ok(Resource::TinyCloud(
            SpaceId::new(did.parse::<DIDBuf>()?, "agent".parse()?).to_resource(
                "delegation".parse()?,
                None,
                None,
                None,
            ),
        ))
    }

    fn header(&self, resource: &Resource, nonce: &str, proofs: Vec<AuthCid>) -> Result<String> {
        let mut capabilities = Capabilities::new();
        capabilities.with_action(
            resource.to_string().parse()?,
            "tinycloud.delegation/list".parse::<UcanAbility>()?,
            [std::collections::BTreeMap::<String, serde_json::Value>::new()],
        );
        Ok(Payload {
            issuer: self.vm.parse::<DIDURLBuf>()?,
            audience: self.did.parse::<DIDBuf>()?,
            not_before: None,
            expiration: NumericDate::try_from_seconds(4_102_444_800.0)?,
            nonce: Some(nonce.to_string()),
            facts: Some(Vec::<serde_json::Value>::new()),
            proof: proofs,
            attenuation: capabilities,
        }
        .sign(self.jwk.get_algorithm().unwrap_or_default(), &self.jwk)?
        .encode()?)
    }
}

/// Rows are seeded in one transaction that `serve` commits before the first
/// request.
struct Fixture {
    tempdir: TempDir,
    tinycloud: TinyCloud,
    conn: tinycloud_core::sea_orm::DatabaseTransaction,
}

impl Fixture {
    async fn new() -> Result<Self> {
        let (tempdir, tinycloud) = test_tinycloud().await?;
        let conn = tinycloud.readable().await?;
        Ok(Self {
            tempdir,
            tinycloud,
            conn,
        })
    }

    async fn serve(self) -> Result<Served> {
        self.conn.commit().await?;
        let rocket = rocket::build()
            .mount("/", rocket::routes![delegation_query])
            .attach(crate::tracing::TracingFairing::for_test(
                &Config::default().log.tracing,
            ))
            .manage(self.tinycloud);
        Ok(Served {
            _tempdir: self.tempdir,
            client: Client::tracked(rocket).await?,
        })
    }

    async fn actor(&self, did: &str) -> Result<()> {
        actor::ActiveModel {
            id: Set(did.to_string()),
        }
        .insert(&self.conn)
        .await?;
        Ok(())
    }

    /// A delegation row with one ability on `resource`.
    async fn delegation(
        &self,
        label: &str,
        delegator: &str,
        delegatee: &str,
        issued_at: i64,
        resource: Resource,
        ability: &str,
    ) -> Result<Hash> {
        let id = tinycloud_core::hash::hash(label.as_bytes());
        delegation::ActiveModel {
            id: Set(id),
            delegator: Set(delegator.to_string()),
            delegatee: Set(delegatee.to_string()),
            expiry: Set(None),
            issued_at: Set(Some(OffsetDateTime::from_unix_timestamp(issued_at)?)),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(label.as_bytes().to_vec()),
        }
        .insert(&self.conn)
        .await?;
        abilities::ActiveModel {
            delegation: Set(id),
            resource: Set(resource),
            ability: Set(Ability::try_from(ability.to_string())?),
            caveats: Set(Default::default()),
        }
        .insert(&self.conn)
        .await?;
        Ok(id)
    }
}

struct Served {
    _tempdir: TempDir,
    client: Client,
}

impl Served {
    async fn query(&self, header: String, body: serde_json::Value) -> (Status, String) {
        let response = self
            .client
            .post("/delegation/query")
            .header(Header::new("Authorization", header))
            .header(ContentType::JSON)
            .body(body.to_string())
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }
}

fn kv_resource(space_did: &str, path: &str) -> Result<Resource> {
    Ok(Resource::TinyCloud(
        SpaceId::new(space_did.parse::<DIDBuf>()?, "files".parse()?).to_resource(
            "kv".parse()?,
            Some(path.parse()?),
            None,
            None,
        ),
    ))
}

fn cids(ids: &[Hash]) -> Vec<String> {
    let mut ids = ids.to_vec();
    ids.sort();
    ids.iter().map(|id| id.to_cid(0x55).to_string()).collect()
}

fn page_cids(body: &str) -> Result<Vec<String>> {
    let page: serde_json::Value = serde_json::from_str(body)?;
    Ok(page["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["cid"].as_str().expect("cid").to_string())
        .collect())
}

#[tokio::test]
async fn issued_lists_only_the_invokers_own_delegations() -> Result<()> {
    let fixture = Fixture::new().await?;
    let (a, b) = (Agent::new()?, Agent::new()?);
    let recipient = "did:key:zIssuedRecipient";
    for did in [&a.did, &b.did, &recipient.to_string()] {
        fixture.actor(did).await?;
    }
    let mut a_issued = Vec::new();
    for n in 0..3 {
        a_issued.push(
            fixture
                .delegation(
                    &format!("a-issued-{n}"),
                    &a.did,
                    recipient,
                    1_700_000_000 + n,
                    kv_resource(&a.did, "notes")?,
                    "tinycloud.kv/get",
                )
                .await?,
        );
    }
    let mut b_issued = Vec::new();
    for n in 0..2 {
        b_issued.push(
            fixture
                .delegation(
                    &format!("b-issued-{n}"),
                    &b.did,
                    recipient,
                    1_700_000_000 + n,
                    kv_resource(&b.did, "notes")?,
                    "tinycloud.kv/get",
                )
                .await?,
        );
    }
    // Rows A received, from B and from the recipient, never appear for A.
    // B issued the one to A, so it is in B's list.
    b_issued.push(
        fixture
            .delegation(
                "b-to-a",
                &b.did,
                &a.did,
                1_700_000_000,
                kv_resource(&b.did, "notes")?,
                "tinycloud.kv/get",
            )
            .await?,
    );
    b_issued.push(
        fixture
            .delegation(
                "b-issued-2",
                &b.did,
                recipient,
                1_700_000_005,
                kv_resource(&b.did, "notes")?,
                "tinycloud.kv/get",
            )
            .await?,
    );
    fixture
        .delegation(
            "recipient-to-a",
            recipient,
            &a.did,
            1_700_000_000,
            kv_resource(recipient, "notes")?,
            "tinycloud.kv/get",
        )
        .await?;

    let fixture = fixture.serve().await?;
    let body = serde_json::json!({ "direction": "issued" });
    let (status, text) = fixture
        .query(
            a.header(&a.list_resource(&a.did)?, "issued-a", vec![])?,
            body.clone(),
        )
        .await;
    assert_eq!(status, Status::Ok, "{text}");
    assert_eq!(
        page_cids(&text)?,
        cids(&a_issued),
        "A sees exactly its three"
    );
    let page: serde_json::Value = serde_json::from_str(&text)?;
    assert_eq!(page["schemaVersion"], 2);
    assert!(page.get("nextCursor").is_none());
    for item in page["items"].as_array().unwrap() {
        assert_eq!(item["direction"], "granted");
        assert_eq!(item["delegatorDid"], a.did.as_str());
    }

    let (status, text) = fixture
        .query(
            b.header(&b.list_resource(&b.did)?, "issued-b", vec![])?,
            body,
        )
        .await;
    assert_eq!(status, Status::Ok, "{text}");
    assert_eq!(page_cids(&text)?, cids(&b_issued), "B sees only its own");
    Ok(())
}

#[tokio::test]
async fn issued_refuses_a_proof_or_another_principals_resource() -> Result<()> {
    let fixture = Fixture::new().await?;
    let (a, b) = (Agent::new()?, Agent::new()?);
    for did in [&a.did, &b.did] {
        fixture.actor(did).await?;
    }
    fixture
        .delegation(
            "a-issued",
            &a.did,
            &b.did,
            1_700_000_000,
            kv_resource(&a.did, "notes")?,
            "tinycloud.kv/get",
        )
        .await?;
    // Valid proofs for the list capability: A over its own DID, and B's grant
    // of B's DID to A.
    let a_self = fixture
        .delegation(
            "a-self-list",
            &a.did,
            &a.did,
            1_700_000_000,
            a.list_resource(&a.did)?,
            "tinycloud.delegation/list",
        )
        .await?;
    let b_to_a = fixture
        .delegation(
            "b-list-to-a",
            &b.did,
            &a.did,
            1_700_000_000,
            b.list_resource(&b.did)?,
            "tinycloud.delegation/list",
        )
        .await?;
    let fixture = fixture.serve().await?;
    let issued = serde_json::json!({ "direction": "issued" });

    let (status, text) = fixture
        .query(
            a.header(&a.list_resource(&a.did)?, "control", vec![])?,
            issued.clone(),
        )
        .await;
    assert_eq!(status, Status::Ok, "no-proof control: {text}");

    for (label, header) in [
        (
            "with a proof",
            a.header(
                &a.list_resource(&a.did)?,
                "with-proof",
                vec![a_self.to_cid(0x55)],
            )?,
        ),
        (
            "capability on another DID, no proof",
            a.header(&a.list_resource(&b.did)?, "other-did", vec![])?,
        ),
        (
            "capability on another DID, with B's grant as proof",
            a.header(
                &a.list_resource(&b.did)?,
                "other-did-proof",
                vec![b_to_a.to_cid(0x55)],
            )?,
        ),
    ] {
        let (status, text) = fixture.query(header, issued.clone()).await;
        assert_eq!(status, Status::Forbidden, "{label}: {text}");
        assert_eq!(text, "Delegation query proof is not authorized", "{label}");
    }

    // A narrower path than the whole delegation service is refused too.
    let narrow = Resource::TinyCloud(
        SpaceId::new(a.did.parse::<DIDBuf>()?, "agent".parse()?).to_resource(
            "delegation".parse()?,
            Some("narrow".parse()?),
            None,
            None,
        ),
    );
    let (status, _) = fixture
        .query(a.header(&narrow, "narrow", vec![])?, issued)
        .await;
    assert_eq!(status, Status::Forbidden);

    // The did:pkh-only gate of the other directions is unchanged.
    for direction in ["granted", "received", "all"] {
        let (status, _) = fixture
            .query(
                a.header(&a.list_resource(&a.did)?, direction, vec![])?,
                serde_json::json!({ "direction": direction }),
            )
            .await;
        assert_eq!(status, Status::Forbidden, "{direction}");
    }
    Ok(())
}

#[tokio::test]
async fn issued_pages_over_http_and_refuses_foreign_cursors_like_garbage() -> Result<()> {
    let fixture = Fixture::new().await?;
    let (a, b) = (Agent::new()?, Agent::new()?);
    for did in [&a.did, &b.did, &"did:key:zIssuedRecipient".to_string()] {
        fixture.actor(did).await?;
    }
    let mut a_issued = Vec::new();
    let mut b_issued = Vec::new();
    for n in 0..5 {
        for (agent, ids) in [(&a, &mut a_issued), (&b, &mut b_issued)] {
            ids.push(
                fixture
                    .delegation(
                        &format!("{}-{n}", agent.did),
                        &agent.did,
                        "did:key:zIssuedRecipient",
                        1_700_000_000,
                        kv_resource(&agent.did, "notes")?,
                        "tinycloud.kv/get",
                    )
                    .await,
            );
        }
    }
    let a_issued = a_issued.into_iter().collect::<Result<Vec<_>>>()?;
    let b_issued = b_issued.into_iter().collect::<Result<Vec<_>>>()?;

    let fixture = fixture.serve().await?;
    // Paging over HTTP: 2 + 2 + 1, each row once, ending without a cursor.
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let mut body = serde_json::json!({ "direction": "issued", "limit": 2 });
        if let Some(cursor) = &cursor {
            body["cursor"] = cursor.as_str().into();
        }
        let (status, text) = fixture
            .query(
                a.header(&a.list_resource(&a.did)?, &format!("page-{pages}"), vec![])?,
                body,
            )
            .await;
        assert_eq!(status, Status::Ok, "{text}");
        seen.extend(page_cids(&text)?);
        let page: serde_json::Value = serde_json::from_str(&text)?;
        cursor = page["nextCursor"].as_str().map(str::to_string);
        pages += 1;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!((pages, seen), (3, cids(&a_issued)));

    // B's own first page yields a cursor that is not A's.
    let (_, text) = fixture
        .query(
            b.header(&b.list_resource(&b.did)?, "b-page", vec![])?,
            serde_json::json!({ "direction": "issued", "limit": 2 }),
        )
        .await;
    let b_cursor = serde_json::from_str::<serde_json::Value>(&text)?["nextCursor"]
        .as_str()
        .expect("B has more rows")
        .to_string();
    let a_cursor = {
        let (_, text) = fixture
            .query(
                a.header(&a.list_resource(&a.did)?, "a-page", vec![])?,
                serde_json::json!({ "direction": "issued", "limit": 2 }),
            )
            .await;
        serde_json::from_str::<serde_json::Value>(&text)?["nextCursor"]
            .as_str()
            .expect("A has more rows")
            .to_string()
    };

    let mut answers = Vec::new();
    let encode = |text: &str| DelegationQuery::encode_cursor(text);
    for (n, cursor) in [
        ("not base64!".to_string()),
        encode("garbage"),
        b_cursor,
        encode(&b_issued[0].to_cid(0x55).to_string()),
    ]
    .into_iter()
    .enumerate()
    {
        let (status, text) = fixture
            .query(
                a.header(
                    &a.list_resource(&a.did)?,
                    &format!("bad-cursor-{n}"),
                    vec![],
                )?,
                serde_json::json!({ "direction": "issued", "limit": 2, "cursor": cursor }),
            )
            .await;
        answers.push((status, text));
    }
    // A's own cursor under a different status filter is foreign too.
    let (status, text) = fixture
        .query(
            a.header(&a.list_resource(&a.did)?, "bad-filter", vec![])?,
            serde_json::json!({
                "direction": "issued", "limit": 2, "status": "active", "cursor": a_cursor
            }),
        )
        .await;
    answers.push((status, text));
    assert_eq!(answers[0].0, Status::BadRequest, "{answers:?}");
    for answer in &answers {
        assert_eq!(answer, &answers[0], "one error for every bad cursor");
    }
    Ok(())
}

/// `granted`, `received` and `all` answer with the same bytes as before the
/// `issued` direction existed. The expected strings are written out here in
/// the response field order; only resource and caveat spellings come from
/// their own serializers.
#[tokio::test]
async fn issued_direction_leaves_granted_received_all_bytes_unchanged() -> Result<()> {
    let fixture = Fixture::new().await?;
    let holder = Agent::new()?;
    let wallet = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
    let peer = "did:key:zIssuedPeer";
    for did in [holder.did.as_str(), wallet, peer] {
        fixture.actor(did).await?;
    }
    let control = SpaceId::new(wallet.parse::<DIDBuf>()?, "control".parse()?);
    let list_resource = Resource::TinyCloud(control.clone().to_resource(
        "delegation".parse()?,
        None,
        None,
        None,
    ));
    let notes =
        Resource::TinyCloud(control.to_resource("kv".parse()?, Some("notes".parse()?), None, None));
    let session = fixture
        .delegation(
            "bytes-session",
            wallet,
            &holder.did,
            1_700_000_100,
            list_resource.clone(),
            "tinycloud.delegation/list",
        )
        .await?;
    let received = fixture
        .delegation(
            "bytes-received",
            peer,
            wallet,
            1_700_000_000,
            notes.clone(),
            "tinycloud.kv/get",
        )
        .await?;
    let granted = fixture
        .delegation(
            "bytes-granted",
            wallet,
            peer,
            1_700_000_200,
            notes.clone(),
            "tinycloud.kv/get",
        )
        .await?;

    let fixture = fixture.serve().await?;
    let caveats = serde_json::to_string(&tinycloud_core::types::Caveats::default())?;
    let item = |id: Hash,
                direction: &str,
                delegator: &str,
                delegatee: &str,
                resource: &Resource,
                ability: &str,
                issued_at: &str| {
        format!(
            "{{\"cid\":\"{}\",\"direction\":\"{direction}\",\"delegatorDid\":\"{delegator}\",\
             \"delegateDid\":\"{delegatee}\",\"resources\":[{{\"resource\":\"{resource}\",\
             \"actions\":[\"{ability}\"],\"caveats\":[{caveats}]}}],\"parents\":[],\
             \"issuedAt\":\"{issued_at}\",\"notBefore\":null,\"expiresAt\":null,\
             \"status\":\"active\"}}",
            id.to_cid(0x55)
        )
    };
    let granted_item = item(
        granted,
        "granted",
        wallet,
        peer,
        &notes,
        "tinycloud.kv/get",
        "2023-11-14T22:16:40Z",
    );
    let session_item = item(
        session,
        "granted",
        wallet,
        &holder.did,
        &list_resource,
        "tinycloud.delegation/list",
        "2023-11-14T22:15:00Z",
    );
    let received_item = item(
        received,
        "received",
        peer,
        wallet,
        &notes,
        "tinycloud.kv/get",
        "2023-11-14T22:13:20Z",
    );

    let header = |nonce: &str| holder.header(&list_resource, nonce, vec![session.to_cid(0x55)]);
    for (label, body, items) in [
        (
            "all (default)",
            serde_json::json!({}),
            vec![&granted_item, &session_item, &received_item],
        ),
        (
            "all",
            serde_json::json!({ "direction": "all" }),
            vec![&granted_item, &session_item, &received_item],
        ),
        (
            "granted",
            serde_json::json!({ "direction": "granted" }),
            vec![&granted_item, &session_item],
        ),
        (
            "received",
            serde_json::json!({ "direction": "received" }),
            vec![&received_item],
        ),
    ] {
        let (status, text) = fixture.query(header(label)?, body).await;
        assert_eq!(status, Status::Ok, "{label}: {text}");
        let expected = format!(
            "{{\"schemaVersion\":2,\"items\":[{}]}}",
            items
                .iter()
                .map(|item| item.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(text, expected, "{label}");
    }
    Ok(())
}

/// `/info` advertises `delegation-issued-query-v1` unconditionally.
#[tokio::test]
async fn issued_query_feature_is_advertised_by_info() -> Result<()> {
    let fixture = KvSyncFixture::new_configured(Config::default(), |rocket| rocket).await?;
    let response = fixture.client.get("/info").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let info: serde_json::Value =
        serde_json::from_str(&response.into_string().await.unwrap_or_default())?;
    assert!(
        info["features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|feature| feature == "delegation-issued-query-v1"),
        "{info}"
    );
    Ok(())
}
