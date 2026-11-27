use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use serde_json::{json, Value};
use tinycloud_core::encryption_network::NetworkId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

use super::binding::{self, BindingError};
use super::record::{self, KeyRecord};
use super::*;

const APP_ID: &str = "0b1c3a7e9f2d4c6b8a0e1f2d3c4b5a6978877665";
const INSTANCE_ID: &str = "5f4e3d2c1b0a99887766554433221100ffeeddcc";

fn network(name: &str) -> NetworkId {
    NetworkId::new("did:key:z6MkTestAbcd", name).unwrap()
}

fn identity() -> LocalIdentity {
    LocalIdentity {
        app_id: APP_ID.into(),
        instance_id: INSTANCE_ID.into(),
    }
}

// ---------------------------------------------------------------------------
// A dstack guest agent on a temporary socket that answers /Info and
// /GetQuote and fails every other path, /GetKey included.
// ---------------------------------------------------------------------------

struct FakeDstack {
    _dir: tempfile::TempDir,
    socket: String,
    paths: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeDstack {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Holds `/GetQuote` open: `entered` fires when a quote request arrives, and
/// the reply waits for `release`.
#[derive(Default)]
struct QuoteGate {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl FakeDstack {
    fn new(app_id: &str, instance_id: &str) -> Self {
        Self::serve(app_id, instance_id, None)
    }

    fn gated(app_id: &str, instance_id: &str) -> (Self, Arc<QuoteGate>) {
        let gate = Arc::new(QuoteGate::default());
        (Self::serve(app_id, instance_id, Some(gate.clone())), gate)
    }

    fn serve(app_id: &str, instance_id: &str, gate: Option<Arc<QuoteGate>>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("dstack.sock").to_str().unwrap().to_owned();
        let listener = UnixListener::bind(&socket).unwrap();
        let paths = Arc::new(Mutex::new(Vec::new()));
        let info = json!({"app_id": app_id, "compose_hash": "00", "instance_id": instance_id});
        let seen = paths.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let seen = seen.clone();
                let info = info.clone();
                let gate = gate.clone();
                tokio::spawn(async move {
                    let mut raw = Vec::new();
                    stream.read_to_end(&mut raw).await.unwrap();
                    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
                    let path = head.split(' ').nth(1).unwrap().to_owned();
                    seen.lock().unwrap().push(path.clone());
                    let (status, body) = match path.as_str() {
                        "/Info" => ("200 OK", info.to_string()),
                        "/GetQuote" => {
                            if let Some(gate) = &gate {
                                gate.entered.notify_one();
                                gate.release.notified().await;
                            }
                            let body: Value = serde_json::from_slice(&raw[split + 4..]).unwrap();
                            let mut padded =
                                hex::decode(body["report_data"].as_str().unwrap()).unwrap();
                            padded.resize(64, 0);
                            let reply = json!({
                                "quote": hex::encode(crate::dstack::stub::tdx_quote(&padded)),
                                "event_log": "[{\"event\":\"compose-hash\"}]",
                                "report_data": hex::encode(&padded),
                            });
                            ("200 OK", reply.to_string())
                        }
                        _ => (
                            "500 Internal Server Error",
                            r#"{"error":"key derivation is disabled in this test"}"#.to_owned(),
                        ),
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                    stream.shutdown().await.unwrap();
                });
            }
        });
        Self {
            _dir: dir,
            socket,
            paths,
            task,
        }
    }

    fn paths(&self) -> Vec<String> {
        self.paths.lock().unwrap().clone()
    }

    /// Every path requested so far is `/Info` or `/GetQuote`.
    fn assert_no_key_derivation(&self) {
        let paths = self.paths();
        assert!(
            paths.iter().all(|p| p == "/Info" || p == "/GetQuote"),
            "{paths:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Caller-supplied seams.
// ---------------------------------------------------------------------------

struct Admit;

#[async_trait]
impl OwnerAdmission for Admit {
    async fn verify(&self, _: &NetworkId, _: &Value) -> Result<(), AdmissionRefused> {
        Ok(())
    }
}

struct Refuse;

#[async_trait]
impl OwnerAdmission for Refuse {
    async fn verify(&self, _: &NetworkId, _: &Value) -> Result<(), AdmissionRefused> {
        Err(AdmissionRefused("no owner admission".into()))
    }
}

#[derive(Default)]
struct Holdings(Mutex<HashSet<String>>);

impl Holdings {
    fn hold(&self, network: &NetworkId) {
        self.0.lock().unwrap().insert(network.to_string());
    }
    fn release(&self, network: &NetworkId) {
        self.0.lock().unwrap().remove(&network.to_string());
    }
}

impl MemberHoldings for Holdings {
    fn holds_share_or_candidate(&self, network: &NetworkId) -> anyhow::Result<bool> {
        Ok(self.0.lock().unwrap().contains(&network.to_string()))
    }
}

/// This node's network rows: one backend per network URN.
#[derive(Default)]
struct Rows(Mutex<std::collections::HashMap<String, KeyBackendKind>>);

impl Rows {
    fn insert(&self, network: &NetworkId, backend: KeyBackendKind) {
        self.0.lock().unwrap().insert(network.to_string(), backend);
    }
}

#[async_trait]
impl NetworkRows for Rows {
    async fn backend(&self, network: &NetworkId) -> anyhow::Result<Option<KeyBackendKind>> {
        Ok(self.0.lock().unwrap().get(&network.to_string()).copied())
    }
}

struct Fixture {
    share: tempfile::TempDir,
    keys: MemberKeys,
    holdings: Holdings,
    rows: Rows,
}

impl Fixture {
    fn new() -> Self {
        let share = tempfile::tempdir().unwrap();
        let keys = MemberKeys::new(share.path());
        Self {
            share,
            keys,
            holdings: Holdings::default(),
            rows: Rows::default(),
        }
    }

    fn key_path(&self, network: &NetworkId) -> std::path::PathBuf {
        record::network_dir(self.share.path(), &network.to_string()).join(record::KEY_FILE)
    }

    /// A time past the TTL of `network`'s key record. The TTL runs from the
    /// record's mtime, which is later than any clock read before the
    /// install.
    fn past_ttl(&self, network: &NetworkId) -> SystemTime {
        std::fs::metadata(self.key_path(network))
            .unwrap()
            .modified()
            .unwrap()
            + PENDING_KEY_TTL
            + Duration::from_secs(1)
    }

    async fn attest(
        &self,
        dstack: &FakeDstack,
        network: &str,
        nonce: &[u8; 32],
        admission: &dyn OwnerAdmission,
    ) -> AttestationOutcome {
        let ctx = MemberAttestation {
            keys: &self.keys,
            dstack_socket: &dstack.socket,
            holdings: &self.holdings,
            networks: &self.rows,
        };
        member_attestation(
            &ctx,
            network,
            &json!({ "nonce": hex::encode(nonce) }),
            admission,
        )
        .await
    }

    fn admit(
        &self,
        network: &NetworkId,
        now: SystemTime,
    ) -> Result<MemberPublicKey, MemberKeyError> {
        self.keys
            .admit(network, &identity(), &self.holdings, now, &mut Vec::new())
    }

    fn expire(&self, now: SystemTime) -> Result<Vec<MemberKeyAudit>, MemberKeyError> {
        let mut audit = Vec::new();
        self.keys
            .expire_pending(&self.holdings, &identity(), now, &mut audit)?;
        Ok(audit)
    }

    fn unlink(&self, network: &NetworkId) -> Result<MemberKeyAudit, MemberKeyError> {
        self.keys
            .unlink_after_last_share(network, &identity(), &self.holdings)
    }
}

fn verify(network: &NetworkId, nonce: &[u8; 32], response: &AttestationResponse) -> String {
    let member_pk: [u8; 32] = hex::decode(&response.member_pk)
        .unwrap()
        .try_into()
        .unwrap();
    let pop_sig: [u8; 64] = hex::decode(&response.pop_sig).unwrap().try_into().unwrap();
    binding::verify_member_attestation(
        &network.to_string(),
        nonce,
        &member_pk,
        &hex::decode(&response.quote).unwrap(),
        &pop_sig,
    )
    .unwrap()
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

// ---------------------------------------------------------------------------
// D7.3 handler, binding and the no-key-derivation invariant.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn attestation_installs_one_key_and_binds_it_to_the_quote() {
    let dstack = FakeDstack::new(APP_ID, INSTANCE_ID);
    let fx = Fixture::new();
    let net = network("default");
    let nonce = [7u8; 32];

    let outcome = fx.attest(&dstack, &net.to_string(), &nonce, &Admit).await;
    let response = outcome.result.unwrap();
    assert!(outcome.audit.is_empty(), "{:?}", outcome.audit);
    assert_eq!(response.event_log, "[{\"event\":\"compose-hash\"}]");
    let did = verify(&net, &nonce, &response);
    assert_eq!(did, fx.keys.load(&net, &identity()).unwrap().did());

    let key = fx.key_path(&net);
    assert_eq!(mode(&key), 0o600);
    assert_eq!(mode(key.parent().unwrap()), 0o700);
    assert_eq!(mode(&fx.share.path().join("member")), 0o700);
    let stored = KeyRecord::decode(&std::fs::read(&key).unwrap()).unwrap();
    assert_eq!(stored.network, net.to_string());
    assert_eq!(stored.identity, identity());

    // A second admission returns the same installed key with a fresh binding.
    let again = fx
        .attest(&dstack, &net.to_string(), &[8u8; 32], &Admit)
        .await;
    let again = again.result.unwrap();
    assert_eq!(again.member_pk, response.member_pk);
    assert_eq!(verify(&net, &[8u8; 32], &again), did);
    dstack.assert_no_key_derivation();
}

#[tokio::test]
async fn the_handler_binds_the_canonical_urn_not_the_path_spelling() {
    let dstack = FakeDstack::new(APP_ID, INSTANCE_ID);
    let fx = Fixture::new();
    let path = "urn:tinycloud:encryption:did:pkh:eip155:1:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266:default";
    let canonical: NetworkId = path.parse().unwrap();
    assert_ne!(canonical.to_string(), path);
    let nonce = [3u8; 32];
    let response = fx
        .attest(&dstack, path, &nonce, &Admit)
        .await
        .result
        .unwrap();
    verify(&canonical, &nonce, &response);
    let member_pk: [u8; 32] = hex::decode(&response.member_pk)
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        binding::report_data(path, &member_pk, &nonce),
        Err(BindingError::NoncanonicalNetwork)
    );
}

#[tokio::test]
async fn every_member_key_path_runs_without_key_derivation() {
    let dstack = FakeDstack::new(APP_ID, INSTANCE_ID);
    let fx = Fixture::new();
    let net = network("default");
    let other = network("other");

    fx.attest(&dstack, &net.to_string(), &[1; 32], &Admit)
        .await
        .result
        .unwrap();
    fx.attest(&dstack, &other.to_string(), &[1; 32], &Refuse)
        .await
        .result
        .unwrap_err();
    fx.attest(&dstack, &net.to_string(), &[2; 32], &Admit)
        .await
        .result
        .unwrap();
    let identity = LocalIdentity::read(&dstack.socket).await.unwrap();
    fx.keys.load(&net, &identity).unwrap();
    fx.expire(SystemTime::now() + PENDING_KEY_TTL).unwrap();
    fx.attest(&dstack, &net.to_string(), &[3; 32], &Admit)
        .await
        .result
        .unwrap();
    fx.unlink(&net).unwrap();

    assert!(dstack.paths().contains(&"/GetQuote".to_owned()));
    dstack.assert_no_key_derivation();
}

#[test]
fn member_key_sources_never_reach_the_key_derivation_or_key_provider() {
    let sources = [
        (
            "threshold_member.rs",
            include_str!("../threshold_member.rs"),
        ),
        ("record.rs", include_str!("record.rs")),
        ("binding.rs", include_str!("binding.rs")),
        ("admission.rs", include_str!("admission.rs")),
    ];
    let forbidden = [
        concat!("get", "_key"),
        concat!("Get", "Key"),
        concat!("dstack", "_kms"),
        concat!("root", "_wrap"),
        concat!("core::", "keys"),
        concat!("Static", "Secret"),
    ];
    for (file, source) in sources {
        for needle in forbidden {
            assert!(!source.contains(needle), "{file} references {needle}");
        }
    }
}

#[tokio::test]
async fn the_handler_accepts_only_a_canonical_nonce_body() {
    let dstack = FakeDstack::new(APP_ID, INSTANCE_ID);
    let fx = Fixture::new();
    let net = network("default");
    let ctx = MemberAttestation {
        keys: &fx.keys,
        dstack_socket: &dstack.socket,
        holdings: &fx.holdings,
        networks: &fx.rows,
    };
    let bodies = [
        json!({}),
        json!({ "nonce": "07".repeat(31) }),
        json!({ "nonce": "AB".repeat(32) }),
        json!({ "nonce": "0x".to_owned() + &"07".repeat(31) }),
        json!({ "nonce": "07".repeat(32), "report_data": "00".repeat(64) }),
        json!({ "nonce": "07".repeat(32), "member_pk": "00".repeat(32) }),
    ];
    for body in bodies {
        let outcome = member_attestation(&ctx, &net.to_string(), &body, &Admit).await;
        assert!(
            matches!(outcome.result, Err(MemberKeyError::InvalidRequest(_))),
            "{body}: {:?}",
            outcome.result
        );
        assert_eq!(outcome.audit[0].reason, "invalid-request");
    }
    assert!(!fx.share.path().join("member").exists());
    assert!(dstack.paths().is_empty());
}

#[tokio::test]
async fn concurrent_admissions_all_get_the_one_installed_key() {
    let dstack = Arc::new(FakeDstack::new(APP_ID, INSTANCE_ID));
    let fx = Arc::new(Fixture::new());
    let net = network("default");
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..8u8 {
        let (dstack, fx, net) = (dstack.clone(), fx.clone(), net.to_string());
        tasks.spawn(async move { fx.attest(&dstack, &net, &[i; 32], &Admit).await.result });
    }
    let mut keys = HashSet::new();
    while let Some(result) = tasks.join_next().await {
        keys.insert(result.unwrap().unwrap().member_pk);
    }
    assert_eq!(keys.len(), 1);
}

#[test]
fn concurrent_installs_have_one_winner_on_disk() {
    let share = tempfile::tempdir().unwrap();
    let dir = record::network_dir(share.path(), &network("default").to_string());
    let barrier = Arc::new(std::sync::Barrier::new(16));
    let threads: Vec<_> = (0..16)
        .map(|_| {
            let (dir, barrier) = (dir.clone(), barrier.clone());
            std::thread::spawn(move || {
                let candidate = KeyRecord::generate(&network("default").to_string(), &identity());
                barrier.wait();
                let installed = record::install_or_load(&dir, candidate).unwrap();
                *installed.seed
            })
        })
        .collect();
    let seeds: HashSet<[u8; 32]> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(seeds.len(), 1);
    let on_disk = KeyRecord::decode(&std::fs::read(dir.join(record::KEY_FILE)).unwrap()).unwrap();
    assert!(seeds.contains(&*on_disk.seed));
    let names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["key"], "losing candidates are removed");
}

// ---------------------------------------------------------------------------
// D7.1 identity binding and record validation.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_record_of_another_app_or_instance_is_refused_and_kept() {
    let fx = Fixture::new();
    let net = network("default");
    let did = fx.admit(&net, SystemTime::now()).unwrap().did();
    let bytes = std::fs::read(fx.key_path(&net)).unwrap();

    for (other, field) in [
        (
            LocalIdentity {
                app_id: "ffff".into(),
                instance_id: INSTANCE_ID.into(),
            },
            "app_id",
        ),
        (
            LocalIdentity {
                app_id: APP_ID.into(),
                instance_id: "ffff".into(),
            },
            "instance_id",
        ),
    ] {
        let err = fx.keys.load(&net, &other).unwrap_err();
        assert!(
            matches!(err, MemberKeyError::IdentityMismatch(f) if f == field),
            "{err}"
        );
        let err = fx
            .keys
            .admit(
                &net,
                &other,
                &fx.holdings,
                SystemTime::now(),
                &mut Vec::new(),
            )
            .unwrap_err();
        assert!(
            matches!(err, MemberKeyError::IdentityMismatch(f) if f == field),
            "{err}"
        );

        let dstack = FakeDstack::new(&other.app_id, &other.instance_id);
        let outcome = fx.attest(&dstack, &net.to_string(), &[1; 32], &Admit).await;
        assert!(matches!(
            outcome.result,
            Err(MemberKeyError::IdentityMismatch(_))
        ));
        assert_eq!(outcome.audit.len(), 1);
        assert_eq!(outcome.audit[0].event, "member_key_refused");
        assert_eq!(outcome.audit[0].reason, "identity-mismatch");
        assert_eq!(
            dstack.paths(),
            ["/Info"],
            "no quote for a mismatched record"
        );
    }
    assert_eq!(std::fs::read(fx.key_path(&net)).unwrap(), bytes);
    assert_eq!(fx.keys.load(&net, &identity()).unwrap().did(), did);
}

#[test]
fn a_malformed_or_incomplete_record_is_refused_and_kept() {
    let fx = Fixture::new();
    let net = network("default");
    fx.admit(&net, SystemTime::now()).unwrap();
    let good = std::fs::read(fx.key_path(&net)).unwrap();

    let mut wrong_version = good.clone();
    wrong_version[0] = 2;
    let pkh = "urn:tinycloud:encryption:did:pkh:eip155:1:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266:default";
    let noncanonical = KeyRecord {
        network: pkh.into(),
        identity: identity(),
        seed: Zeroizing::new([1; 32]),
    }
    .encode()
    .to_vec();
    let mut zero_length = good.clone();
    zero_length[1..5].copy_from_slice(&0u32.to_be_bytes());
    let cases: [(&str, Vec<u8>); 6] = [
        ("empty", Vec::new()),
        ("truncated seed", good[..good.len() - 1].to_vec()),
        ("trailing byte", [good.as_slice(), &[0]].concat()),
        ("unknown version", wrong_version),
        ("noncanonical network", noncanonical),
        ("empty field", zero_length),
    ];
    for (case, bytes) in cases {
        std::fs::write(fx.key_path(&net), &bytes).unwrap();
        let err = fx.keys.load(&net, &identity()).unwrap_err();
        assert!(
            matches!(err, MemberKeyError::MalformedRecord(_)),
            "{case}: {err}"
        );
        let err = fx.admit(&net, SystemTime::now()).unwrap_err();
        assert!(
            matches!(err, MemberKeyError::MalformedRecord(_)),
            "{case}: {err}"
        );
        assert_eq!(std::fs::read(fx.key_path(&net)).unwrap(), bytes, "{case}");
    }

    std::fs::remove_file(fx.key_path(&net)).unwrap();
    std::os::unix::fs::symlink("/dev/null", fx.key_path(&net)).unwrap();
    let err = fx.keys.load(&net, &identity()).unwrap_err();
    assert!(matches!(err, MemberKeyError::MalformedRecord(_)), "{err}");
}

#[test]
fn a_record_filed_under_another_network_is_refused() {
    let fx = Fixture::new();
    let (net, other) = (network("default"), network("other"));
    fx.admit(&other, SystemTime::now()).unwrap();
    std::fs::create_dir_all(fx.key_path(&net).parent().unwrap()).unwrap();
    std::fs::copy(fx.key_path(&other), fx.key_path(&net)).unwrap();
    let err = fx.keys.load(&net, &identity()).unwrap_err();
    assert!(
        matches!(err, MemberKeyError::IdentityMismatch("network")),
        "{err}"
    );
}

#[test]
fn a_member_holding_a_share_without_a_key_never_generates_one() {
    let fx = Fixture::new();
    let net = network("default");
    fx.holdings.hold(&net);
    let err = fx.admit(&net, SystemTime::now()).unwrap_err();
    assert!(matches!(err, MemberKeyError::KeyMissing), "{err}");
    assert!(!fx.key_path(&net).exists());
}

// ---------------------------------------------------------------------------
// D7.1 owner admission.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn without_an_owner_admission_nothing_is_created() {
    let dstack = FakeDstack::new(APP_ID, INSTANCE_ID);
    let fx = Fixture::new();
    let net = network("default");
    let outcome = fx
        .attest(&dstack, &net.to_string(), &[1; 32], &Refuse)
        .await;
    assert!(matches!(
        outcome.result,
        Err(MemberKeyError::AdmissionRefused(_))
    ));
    assert_eq!(
        outcome.audit,
        [MemberKeyAudit {
            event: "member_key_refused",
            network: net.to_string(),
            member_did: None,
            outcome: "refused",
            reason: "unauthorized",
        }]
    );
    assert!(!fx.share.path().join("member").exists());
    assert!(dstack.paths().is_empty(), "refused before dstack is asked");
}

mod admission_shape {
    use super::*;
    use crate::threshold_member::admission::check_admission_shape;
    use tinycloud_auth::{
        resolver::DID_METHODS,
        ssi::{
            claims::jwt::NumericDate,
            jwk::{Algorithm, JWK},
            ucan::Payload,
        },
        ucan_capabilities_object::{Ability, Capabilities},
    };
    use tinycloud_core::encryption_network::{
        canonical::canonical_hash, NetworkAdminFacts, NETWORK_ADMIN_TYPE, NETWORK_REVOKE_ACTION,
    };
    use tinycloud_core::util::InvocationInfo;

    const NODE: &str = "did:key:z6MkNodeTest";

    fn owner_key() -> JWK {
        let mut jwk = JWK::generate_ed25519().unwrap();
        jwk.algorithm = Some(Algorithm::EdDSA);
        jwk
    }

    /// A fresh invoker's admission whose nonce is the challenge `"07" * 32`.
    fn invocation(audience: &str, resource: &str, ability: &str, facts: Value) -> InvocationInfo {
        signed(
            &owner_key(),
            audience,
            resource,
            ability,
            facts,
            &"07".repeat(32),
        )
    }

    fn signed(
        jwk: &JWK,
        audience: &str,
        resource: &str,
        ability: &str,
        facts: Value,
        nonce: &str,
    ) -> InvocationInfo {
        let did = DID_METHODS.generate(jwk, "key").unwrap().to_string();
        let fragment = did.rsplit_once(':').unwrap().1.to_owned();
        let mut caps = Capabilities::<Value>::new();
        caps.with_action(
            resource.parse().unwrap(),
            ability.parse::<Ability>().unwrap(),
            [],
        );
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let payload = Payload {
            issuer: format!("{did}#{fragment}").parse().unwrap(),
            audience: audience.parse().unwrap(),
            not_before: None,
            expiration: NumericDate::try_from_seconds((now + 60) as f64).unwrap(),
            nonce: Some(nonce.into()),
            facts: Some(vec![facts]),
            proof: vec![],
            attenuation: caps,
        };
        InvocationInfo::try_from(payload.sign(Algorithm::EdDSA, jwk).unwrap()).unwrap()
    }

    fn facts(net: &NetworkId, target: &str, action: &str, body: &Value) -> Value {
        serde_json::to_value(NetworkAdminFacts {
            ty: NETWORK_ADMIN_TYPE.into(),
            target_node: target.into(),
            network_id: net.clone(),
            body_hash: canonical_hash(body),
            action: action.into(),
        })
        .unwrap()
    }

    #[test]
    fn only_a_member_admit_invocation_for_this_node_network_and_body_passes() {
        let net = network("default");
        let body = json!({ "nonce": "07".repeat(32) });
        let ok = invocation(
            NODE,
            &net.to_string(),
            MEMBER_ADMIT_ACTION,
            facts(&net, NODE, MEMBER_ADMIT_ACTION, &body),
        );
        check_admission_shape(&ok, NODE, &net, &body).unwrap();

        let other = network("other");
        let other_body = json!({ "nonce": "08".repeat(32) });
        let refused = [
            (
                "audience",
                invocation(
                    "did:key:z6MkSecondNode",
                    &net.to_string(),
                    MEMBER_ADMIT_ACTION,
                    facts(&net, NODE, MEMBER_ADMIT_ACTION, &body),
                ),
                &body,
            ),
            (
                "ability",
                invocation(
                    NODE,
                    &net.to_string(),
                    NETWORK_REVOKE_ACTION,
                    facts(&net, NODE, MEMBER_ADMIT_ACTION, &body),
                ),
                &body,
            ),
            (
                "resource",
                invocation(
                    NODE,
                    &other.to_string(),
                    MEMBER_ADMIT_ACTION,
                    facts(&net, NODE, MEMBER_ADMIT_ACTION, &body),
                ),
                &body,
            ),
            (
                "target node",
                invocation(
                    NODE,
                    &net.to_string(),
                    MEMBER_ADMIT_ACTION,
                    facts(&net, "did:key:z6MkSecondNode", MEMBER_ADMIT_ACTION, &body),
                ),
                &body,
            ),
            (
                "fact network",
                invocation(
                    NODE,
                    &net.to_string(),
                    MEMBER_ADMIT_ACTION,
                    facts(&other, NODE, MEMBER_ADMIT_ACTION, &body),
                ),
                &body,
            ),
            (
                "fact action",
                invocation(
                    NODE,
                    &net.to_string(),
                    MEMBER_ADMIT_ACTION,
                    facts(&net, NODE, NETWORK_REVOKE_ACTION, &body),
                ),
                &body,
            ),
            (
                "body hash",
                invocation(
                    NODE,
                    &net.to_string(),
                    MEMBER_ADMIT_ACTION,
                    facts(&net, NODE, MEMBER_ADMIT_ACTION, &body),
                ),
                &other_body,
            ),
            (
                "missing fact",
                invocation(NODE, &net.to_string(), MEMBER_ADMIT_ACTION, json!({})),
                &body,
            ),
        ];
        for (case, invocation, body) in refused {
            assert!(
                check_admission_shape(&invocation, NODE, &net, body).is_err(),
                "{case}"
            );
        }
    }

    #[test]
    fn the_invocation_nonce_must_be_the_request_challenge() {
        let net = network("default");
        let body = json!({ "nonce": "07".repeat(32) });
        let fact = facts(&net, NODE, MEMBER_ADMIT_ACTION, &body);
        for nonce in [
            "08".repeat(32),
            "07".repeat(31),
            format!("{}0", "07".repeat(32)),
            "admission".into(),
        ] {
            let mismatched = signed(
                &owner_key(),
                NODE,
                &net.to_string(),
                MEMBER_ADMIT_ACTION,
                fact.clone(),
                &nonce,
            );
            let refused = check_admission_shape(&mismatched, NODE, &net, &body).unwrap_err();
            assert!(refused.0.starts_with("challenge_mismatch"), "{refused}");
        }
        // With the challenge matching, a fact signed over another body is
        // still refused on its hash.
        let other_body = json!({ "nonce": "08".repeat(32) });
        let ok = invocation(
            NODE,
            &net.to_string(),
            MEMBER_ADMIT_ACTION,
            facts(&net, NODE, MEMBER_ADMIT_ACTION, &other_body),
        );
        let refused = check_admission_shape(&ok, NODE, &net, &body).unwrap_err();
        assert!(refused.0.contains("bodyHash"), "{refused}");
    }

    /// The real shape check and challenge consumption, against a real
    /// `EncryptionService`; the owner-authority steps need a full node and
    /// are not part of this seam.
    struct ShapeAndChallenge<'a> {
        invocation: &'a InvocationInfo,
        service: &'a tinycloud_core::encryption_network::EncryptionService,
    }

    #[async_trait]
    impl OwnerAdmission for ShapeAndChallenge<'_> {
        async fn verify(&self, network: &NetworkId, body: &Value) -> Result<(), AdmissionRefused> {
            check_admission_shape(self.invocation, NODE, network, body)?;
            crate::threshold_member::admission::consume_challenge(
                self.service,
                self.invocation,
                time::OffsetDateTime::now_utc(),
            )
            .await
        }
    }

    pub(super) async fn encryption_service() -> (
        tempfile::TempDir,
        tinycloud_core::sea_orm::DatabaseConnection,
        tinycloud_core::encryption_network::EncryptionService,
    ) {
        use tinycloud_core::sea_orm_migration::MigratorTrait;
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}/caps.db?mode=rwc", dir.path().display());
        let db = tinycloud_core::sea_orm::Database::connect(url)
            .await
            .unwrap();
        tinycloud_core::migrations::Migrator::up(&db, None)
            .await
            .unwrap();
        let backend = std::sync::Arc::new(
            tinycloud_core::encryption_network::LocalOneOfOneBackend::new(
                tinycloud_core::encryption::ColumnEncryption::new([0xAB; 32]),
            ),
        );
        let service = tinycloud_core::encryption_network::EncryptionService::new(
            db.clone(),
            NODE.to_string(),
            backend,
        );
        (dir, db, service)
    }

    async fn consumed(db: &tinycloud_core::sea_orm::DatabaseConnection) -> u64 {
        use tinycloud_core::sea_orm::{EntityTrait, PaginatorTrait};
        tinycloud_core::models::encryption_nonce::Entity::find()
            .count(db)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn the_challenge_is_consumed_once_and_a_mismatch_consumes_nothing() {
        let (_db_dir, db, service) = encryption_service().await;
        let dstack = FakeDstack::new(APP_ID, INSTANCE_ID);
        let fx = Fixture::new();
        let net = network("default");
        let challenge = [7u8; 32];
        let body = json!({ "nonce": hex::encode(challenge) });
        let fact = facts(&net, NODE, MEMBER_ADMIT_ACTION, &body);
        let owner = owner_key();
        let admit = |nonce: &str| {
            signed(
                &owner,
                NODE,
                &net.to_string(),
                MEMBER_ADMIT_ACTION,
                fact.clone(),
                nonce,
            )
        };

        let mismatched = admit(&"08".repeat(32));
        let outcome = fx
            .attest(
                &dstack,
                &net.to_string(),
                &challenge,
                &ShapeAndChallenge {
                    invocation: &mismatched,
                    service: &service,
                },
            )
            .await;
        assert!(matches!(
            outcome.result,
            Err(MemberKeyError::AdmissionRefused(_))
        ));
        assert_eq!(outcome.audit[0].reason, "unauthorized");
        assert_eq!(consumed(&db).await, 0);
        assert!(dstack.paths().is_empty(), "no identity read, no quote");
        assert!(!fx.share.path().join("member").exists());

        let first = admit(&hex::encode(challenge));
        let response = fx
            .attest(
                &dstack,
                &net.to_string(),
                &challenge,
                &ShapeAndChallenge {
                    invocation: &first,
                    service: &service,
                },
            )
            .await
            .result
            .unwrap();
        verify(&net, &challenge, &response);
        assert_eq!(consumed(&db).await, 1);
        let requests = dstack.paths().len();

        // A second admission by the same owner key carrying the same C.
        let second = admit(&hex::encode(challenge));
        let outcome = fx
            .attest(
                &dstack,
                &net.to_string(),
                &challenge,
                &ShapeAndChallenge {
                    invocation: &second,
                    service: &service,
                },
            )
            .await;
        let Err(MemberKeyError::AdmissionRefused(refused)) = outcome.result else {
            panic!("replayed challenge admitted: {:?}", outcome.result);
        };
        assert!(refused.0.contains("nonce already used"), "{refused}");
        assert_eq!(consumed(&db).await, 1);
        assert_eq!(dstack.paths().len(), requests, "no quote for a replay");
    }
}

// ---------------------------------------------------------------------------
// D7.1 pending cap and TTL.
// ---------------------------------------------------------------------------

/// Network `name` of the `owner`-th test owner (0..64).
fn owned(owner: usize, name: &str) -> NetworkId {
    const TAGS: &[u8] = b"abcdefgh";
    let tag: String = [TAGS[owner / 8] as char, TAGS[owner % 8] as char]
        .iter()
        .collect();
    NetworkId::new(format!("did:key:z6MkTestPeer{tag}"), name).unwrap()
}

/// Admit [`MAX_PENDING_KEYS`] pending keys, [`MAX_PENDING_KEYS_PER_OWNER`]
/// per owner.
fn fill_pending_cap(fx: &Fixture, now: SystemTime) {
    for i in 0..MAX_PENDING_KEYS {
        let network = owned(i / MAX_PENDING_KEYS_PER_OWNER, &format!("n{i}"));
        fx.admit(&network, now).unwrap();
    }
}

#[tokio::test]
async fn the_owner_pending_cap_refuses_a_third_key_until_one_holds_a_share() {
    let dstack = FakeDstack::new(APP_ID, INSTANCE_ID);
    let fx = Fixture::new();
    let now = SystemTime::now();
    let (first, second, third) = (owned(0, "a"), owned(0, "b"), owned(0, "c"));
    fx.admit(&first, now).unwrap();
    fx.admit(&second, now).unwrap();
    let outcome = fx
        .attest(&dstack, &third.to_string(), &[1; 32], &Admit)
        .await;
    assert!(
        matches!(outcome.result, Err(MemberKeyError::OwnerPendingCapReached)),
        "{:?}",
        outcome.result
    );
    assert_eq!(outcome.audit[0].reason, "owner-pending-cap");
    assert!(!fx.key_path(&third).exists());

    // Another owner is admitted meanwhile.
    let other = owned(1, "a");
    fx.attest(&dstack, &other.to_string(), &[1; 32], &Admit)
        .await
        .result
        .unwrap();
    // An existing pending key is still served at the cap.
    fx.admit(&first, now).unwrap();

    fx.holdings.hold(&first);
    fx.attest(&dstack, &third.to_string(), &[1; 32], &Admit)
        .await
        .result
        .unwrap();
    assert!(fx.key_path(&third).exists());
}

#[test]
fn the_global_pending_cap_refuses_a_key_from_any_owner() {
    let fx = Fixture::new();
    let now = SystemTime::now();
    fill_pending_cap(&fx, now);
    let fresh = owned(MAX_PENDING_KEYS / MAX_PENDING_KEYS_PER_OWNER, "n");
    let err = fx.admit(&fresh, now).unwrap_err();
    assert!(matches!(err, MemberKeyError::PendingCapReached), "{err}");
    assert!(!fx.key_path(&fresh).exists());

    fx.holdings.hold(&owned(0, "n0"));
    fx.admit(&fresh, now).unwrap();
}

#[test]
fn an_expiry_is_audited_even_when_the_admission_is_then_refused() {
    let fx = Fixture::new();
    let now = SystemTime::now();
    let (a, b, c) = (owned(0, "a"), owned(0, "b"), owned(0, "c"));
    // b and c are installed while held, then released: with a, the owner
    // has three pending keys.
    for held in [&b, &c] {
        fx.admit(held, now).unwrap();
        fx.holdings.hold(held);
    }
    let old = fx.admit(&a, now).unwrap().did();
    fx.holdings.release(&b);
    fx.holdings.release(&c);

    let mut audit = Vec::new();
    let err = fx
        .keys
        .admit(&a, &identity(), &fx.holdings, fx.past_ttl(&a), &mut audit)
        .unwrap_err();
    assert!(
        matches!(err, MemberKeyError::OwnerPendingCapReached),
        "{err}"
    );
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].event, "member_key_expired");
    assert_eq!(audit[0].member_did.as_deref(), Some(old.as_str()));
    assert!(!fx.key_path(&a).exists());
}

#[test]
fn a_missing_share_root_is_refused_and_never_created() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("unmounted");
    let keys = MemberKeys::new(&root);
    let err = keys
        .admit(
            &network("default"),
            &identity(),
            &Holdings::default(),
            SystemTime::now(),
            &mut Vec::new(),
        )
        .unwrap_err();
    assert!(matches!(err, MemberKeyError::ShareDirMissing), "{err}");
    assert!(!root.exists());
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn an_overlong_network_is_refused_before_anything_is_created() {
    let dstack = FakeDstack::new(APP_ID, INSTANCE_ID);
    let fx = Fixture::new();
    let overlong = network(&"n".repeat(MAX_URN_BYTES));
    assert!(overlong.to_string().len() > MAX_URN_BYTES);

    let err = fx.admit(&overlong, SystemTime::now()).unwrap_err();
    assert!(matches!(err, MemberKeyError::InvalidNetwork(_)), "{err}");
    let outcome = fx
        .attest(&dstack, &overlong.to_string(), &[1; 32], &Admit)
        .await;
    assert!(
        matches!(outcome.result, Err(MemberKeyError::InvalidNetwork(_))),
        "{:?}",
        outcome.result
    );
    assert!(outcome.audit.is_empty());
    assert!(!fx.share.path().join("member").exists());
    assert!(dstack.paths().is_empty());

    // The longest accepted URN still installs and binds.
    let prefix = network("n").to_string().len() - 1;
    let longest = network(&"n".repeat(MAX_URN_BYTES - prefix));
    assert_eq!(longest.to_string().len(), MAX_URN_BYTES);
    let response = fx
        .attest(&dstack, &longest.to_string(), &[1; 32], &Admit)
        .await
        .result
        .unwrap();
    verify(&longest, &[1; 32], &response);
}

#[test]
fn an_undecodable_record_holds_no_pending_slot_and_is_kept() {
    let fx = Fixture::new();
    let damaged = fx.key_path(&network("damaged"));
    std::fs::create_dir_all(damaged.parent().unwrap()).unwrap();
    std::fs::write(&damaged, b"not a key record").unwrap();

    let now = SystemTime::now();
    fill_pending_cap(&fx, now);
    let fresh = owned(MAX_PENDING_KEYS / MAX_PENDING_KEYS_PER_OWNER, "n");
    let err = fx.admit(&fresh, now).unwrap_err();
    assert!(matches!(err, MemberKeyError::PendingCapReached), "{err}");

    let audit = fx.expire(now + PENDING_KEY_TTL * 2).unwrap();
    assert_eq!(audit.len(), MAX_PENDING_KEYS);
    assert_eq!(std::fs::read(&damaged).unwrap(), b"not a key record");
}

#[test]
fn leftover_temp_records_are_wiped_by_admission_and_the_expiry_sweep() {
    let fx = Fixture::new();
    let (net, other, held) = (network("default"), network("other"), network("held"));
    let now = SystemTime::now();
    fx.admit(&held, now).unwrap();
    fx.holdings.hold(&held);
    // A crash between writing a temp record and unlinking it leaves a
    // seed-bearing file; one with no key beside it, one beside a held key.
    let witnesses = fx.share.path().join("witnesses");
    std::fs::create_dir(&witnesses).unwrap();
    let mut seeded = Vec::new();
    for (i, network) in [&net, &other, &held].into_iter().enumerate() {
        let dir = fx.key_path(network).parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let temp = dir.join("key.tmp-00112233aabbccdd");
        std::fs::write(&temp, [0x5eu8; 113]).unwrap();
        let witness = witnesses.join(i.to_string());
        std::fs::hard_link(&temp, &witness).unwrap();
        seeded.push((temp, witness));
    }

    // Admission wipes the leftovers of its own network.
    fx.admit(&net, now).unwrap();
    assert!(!seeded[0].0.exists());
    assert_eq!(std::fs::read(&seeded[0].1).unwrap(), vec![0u8; 113]);
    assert!(seeded[1].0.exists());

    // The sweep wipes every other leftover and keeps the held key.
    fx.expire(now).unwrap();
    for (temp, witness) in &seeded {
        assert!(!temp.exists(), "{}", temp.display());
        assert_eq!(std::fs::read(witness).unwrap(), vec![0u8; 113]);
    }
    assert!(fx.key_path(&held).exists());
    assert!(fx.key_path(&net).exists());
}

#[tokio::test]
async fn an_unlink_during_the_quote_leaves_the_attestation_unsigned() {
    let (dstack, gate) = FakeDstack::gated(APP_ID, INSTANCE_ID);
    let fx = Fixture::new();
    let net = network("default");
    let urn = net.to_string();
    let unlink = async {
        gate.entered.notified().await;
        let unlinked = fx.unlink(&net).unwrap();
        gate.release.notify_one();
        unlinked
    };
    let (outcome, unlinked) = tokio::join!(fx.attest(&dstack, &urn, &[1; 32], &Admit), unlink);
    assert!(
        matches!(outcome.result, Err(MemberKeyError::Unlinked)),
        "{:?}",
        outcome.result
    );
    assert_eq!(outcome.audit.last().unwrap().reason, "unlinked");
    assert_eq!(unlinked.event, "member_key_unlinked");
    assert!(dstack.paths().contains(&"/GetQuote".to_owned()));
    let dir = fx.key_path(&net).parent().unwrap().to_path_buf();
    assert!(dir.join(record::UNLINKED_FILE).exists());
    assert!(!fx.key_path(&net).exists());
}

#[test]
fn a_sign_after_unlink_or_replacement_is_refused() {
    let fx = Fixture::new();
    let net = network("default");
    let now = SystemTime::now();
    let key = fx.admit(&net, now).unwrap();
    let signature = fx.keys.sign(&net, &key.public_key(), b"message").unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&key.public_key())
        .unwrap()
        .verify_strict(
            b"message",
            &ed25519_dalek::Signature::from_bytes(&signature),
        )
        .unwrap();

    fx.unlink(&net).unwrap();
    let refused = fx.keys.sign(&net, &key.public_key(), b"message");
    assert!(
        matches!(refused, Err(MemberKeyError::Unlinked)),
        "{refused:?}"
    );

    // A new admission installs a new key; the old one still can't sign.
    let replacement = fx.admit(&net, now).unwrap();
    assert_ne!(replacement.public_key(), key.public_key());
    let refused = fx.keys.sign(&net, &key.public_key(), b"message");
    assert!(
        matches!(refused, Err(MemberKeyError::Unlinked)),
        "{refused:?}"
    );
    fx.keys
        .sign(&net, &replacement.public_key(), b"message")
        .unwrap();
}

#[test]
fn a_pending_key_expires_after_the_ttl_and_a_held_one_never_does() {
    let fx = Fixture::new();
    let (pending, held) = (network("pending"), network("held"));
    let now = SystemTime::now();
    let pending_did = fx.admit(&pending, now).unwrap().did();
    fx.admit(&held, now).unwrap();
    fx.holdings.hold(&held);

    let early = now + PENDING_KEY_TTL - Duration::from_secs(60);
    assert!(fx.expire(early).unwrap().is_empty());
    assert_eq!(fx.admit(&pending, early).unwrap().did(), pending_did);

    let late = fx.past_ttl(&pending);
    let audit = fx.expire(late).unwrap();
    assert_eq!(
        audit,
        [MemberKeyAudit {
            event: "member_key_expired",
            network: pending.to_string(),
            member_did: Some(pending_did),
            outcome: "unlinked",
            reason: "pending-ttl",
        }]
    );
    assert!(!fx.key_path(&pending).exists());
    assert!(fx.key_path(&held).exists());
    assert!(fx.expire(late + PENDING_KEY_TTL * 10).unwrap().is_empty());
}

#[test]
fn an_admission_after_the_ttl_replaces_the_expired_pending_key() {
    let fx = Fixture::new();
    let net = network("default");
    let now = SystemTime::now();
    let old = fx.admit(&net, now).unwrap().did();
    let mut audit = Vec::new();
    let key = fx
        .keys
        .admit(
            &net,
            &identity(),
            &fx.holdings,
            fx.past_ttl(&net),
            &mut audit,
        )
        .unwrap();
    assert_ne!(key.did(), old);
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].event, "member_key_expired");
    assert_eq!(audit[0].member_did.as_deref(), Some(old.as_str()));
}

// ---------------------------------------------------------------------------
// D7.4 logical erasure.
// ---------------------------------------------------------------------------

#[test]
fn unlink_after_last_share_zeroes_unlinks_and_records_the_time() {
    let fx = Fixture::new();
    let net = network("default");
    let did = fx.admit(&net, SystemTime::now()).unwrap().did();
    fx.holdings.hold(&net);

    let err = fx.unlink(&net).unwrap_err();
    assert!(matches!(err, MemberKeyError::StillHeld), "{err}");
    assert!(fx.key_path(&net).exists());

    // A second name on the record's inode shows what the unlink wrote.
    let witness = fx.share.path().join("witness");
    std::fs::hard_link(fx.key_path(&net), &witness).unwrap();
    let len = std::fs::metadata(&witness).unwrap().len() as usize;
    let dir = fx.key_path(&net).parent().unwrap().to_path_buf();
    std::fs::write(dir.join("key.tmp-0011223344556677"), [9u8; 40]).unwrap();

    fx.holdings.release(&net);
    let audit = fx.unlink(&net).unwrap();
    assert_eq!(
        audit,
        MemberKeyAudit {
            event: "member_key_unlinked",
            network: net.to_string(),
            member_did: Some(did.clone()),
            outcome: "unlinked",
            reason: "last-share",
        }
    );
    assert_eq!(std::fs::read(&witness).unwrap(), vec![0u8; len]);
    let names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["unlinked"]);
    let unlinked: Value =
        serde_json::from_slice(&std::fs::read(dir.join("unlinked")).unwrap()).unwrap();
    assert_eq!(unlinked["reason"], "last-share");
    assert_eq!(unlinked["member_did"], did.as_str());
    time::OffsetDateTime::parse(
        unlinked["member_key_unlinked_at"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert_eq!(mode(&dir.join("unlinked")), 0o600);

    let err = fx.keys.load(&net, &identity()).unwrap_err();
    assert!(matches!(err, MemberKeyError::NoKey), "{err}");
    let err = fx.unlink(&net).unwrap_err();
    assert!(matches!(err, MemberKeyError::NoKey), "{err}");
}

// ---------------------------------------------------------------------------
// D7.3 known answers and the owner-side check.
// ---------------------------------------------------------------------------

const VECTORS: &str = include_str!("../../tests/fixtures/threshold-member-v1-vectors.json");

fn arr<const N: usize>(v: &Value) -> [u8; N] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn known_answer_vectors() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    for v in vectors["vectors"].as_array().unwrap() {
        let urn = v["network"].as_str().unwrap();
        let record = KeyRecord {
            network: urn.into(),
            identity: identity(),
            seed: Zeroizing::new(arr(&v["seed"])),
        };
        let key = MemberKey::from_record(&record);
        let nonce: [u8; 32] = arr(&v["nonce"]);
        assert_eq!(hex::encode(key.public_key()), v["member_pk"]);
        assert_eq!(key.did(), v["member_did"]);
        let r = binding::report_data(urn, &key.public_key(), &nonce).unwrap();
        assert_eq!(hex::encode(r), v["report_data"]);
        let quote = hex::decode(v["quote"].as_str().unwrap()).unwrap();
        assert_eq!(quote, crate::dstack::stub::tdx_quote(&r));
        let pop = binding::pop_message(urn, &nonce, &quote).unwrap();
        assert_eq!(hex::encode(&pop), v["pop_message"]);
        assert_eq!(hex::encode(key.sign(&pop)), v["pop_sig"]);
        assert_eq!(
            binding::verify_member_attestation(
                urn,
                &nonce,
                &key.public_key(),
                &quote,
                &arr(&v["pop_sig"]),
            )
            .unwrap(),
            v["member_did"].as_str().unwrap()
        );
    }
}

#[test]
fn the_owner_check_reads_reportdata_from_the_quote_and_the_pop_covers_its_bytes() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let v = &vectors["vectors"][0];
    let urn = v["network"].as_str().unwrap();
    let nonce: [u8; 32] = arr(&v["nonce"]);
    let pk: [u8; 32] = arr(&v["member_pk"]);
    let sig: [u8; 64] = arr(&v["pop_sig"]);
    let quote = hex::decode(v["quote"].as_str().unwrap()).unwrap();
    let check = |urn: &str, nonce: &[u8; 32], pk: &[u8; 32], quote: &[u8], sig: &[u8; 64]| {
        binding::verify_member_attestation(urn, nonce, pk, quote, sig)
    };
    check(urn, &nonce, &pk, &quote, &sig).unwrap();

    // A quote over other REPORTDATA fails, whatever an echo would have said.
    let mut other = quote.clone();
    other[48 + 520] ^= 1;
    assert_eq!(
        check(urn, &nonce, &pk, &other, &sig),
        Err(BindingError::ReportDataMismatch)
    );
    // Changing the signature section keeps REPORTDATA but breaks the PoP.
    let mut resigned = quote.clone();
    *resigned.last_mut().unwrap() ^= 1;
    assert_eq!(
        check(urn, &nonce, &pk, &resigned, &sig),
        Err(BindingError::InvalidPop)
    );
    let mut wrong_nonce = nonce;
    wrong_nonce[0] ^= 1;
    assert_eq!(
        check(urn, &wrong_nonce, &pk, &quote, &sig),
        Err(BindingError::ReportDataMismatch)
    );
    let other_urn = network("other").to_string();
    assert_eq!(
        check(&other_urn, &nonce, &pk, &quote, &sig),
        Err(BindingError::ReportDataMismatch)
    );
    let mut bad_sig = sig;
    bad_sig[0] ^= 1;
    assert_eq!(
        check(urn, &nonce, &pk, &quote, &bad_sig),
        Err(BindingError::InvalidPop)
    );
    assert!(matches!(
        check(urn, &nonce, &pk, &quote[..600], &sig),
        Err(BindingError::MalformedQuote(_))
    ));
    // Vector 0 names a did:pkh owner; its lowercase address is not canonical.
    assert!(urn.contains("did:pkh:") && urn != urn.to_lowercase());
    assert_eq!(
        check(&urn.to_lowercase(), &nonce, &pk, &quote, &sig),
        Err(BindingError::NoncanonicalNetwork)
    );
    // The identity point is not a member key.
    let mut identity_point = [0u8; 32];
    identity_point[0] = 1;
    assert_eq!(
        check(urn, &nonce, &identity_point, &quote, &sig),
        Err(BindingError::InvalidMemberKey)
    );
}

// ---------------------------------------------------------------------------
// Key material never reaches a log or a Debug string.
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn key_material_never_appears_in_logs_or_debug_output() {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    // With exactly one registered dispatcher, tracing-core computes a new
    // callsite's interest from the registering thread's default, so a
    // parallel test that first reaches a member-key callsite caches "never"
    // for it. A second registered dispatcher makes registration consult every
    // live dispatcher; the rebuild fixes callsites registered before this.
    let _second = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();

    let dstack = FakeDstack::new(APP_ID, INSTANCE_ID);
    let fx = Fixture::new();
    let net = network("default");
    fx.attest(&dstack, &net.to_string(), &[1; 32], &Admit)
        .await
        .result
        .unwrap();
    fx.attest(&dstack, &net.to_string(), &[1; 32], &Refuse)
        .await
        .result
        .unwrap_err();
    let record = KeyRecord::decode(&std::fs::read(fx.key_path(&net)).unwrap()).unwrap();
    let seed = *record.seed;
    let key = fx.keys.load(&net, &identity()).unwrap();
    let debug = format!("{key:?} {record:?}");
    drop(key);
    fx.unlink(&net).unwrap();

    let mut secret = [0u8; 32];
    Hkdf::<Sha256>::new(None, &seed)
        .expand(SIGN_LABEL, &mut secret)
        .unwrap();
    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("threshold member key unlinked"), "{logs}");
    assert!(
        logs.contains("threshold member attestation refused"),
        "{logs}"
    );
    for text in [&logs, &debug] {
        for material in [seed, secret] {
            for encoded in [
                hex::encode(material),
                hex::encode_upper(material),
                base64::encode(material),
                base64::encode_config(material, base64::URL_SAFE_NO_PAD),
                format!("{material:?}"),
            ] {
                assert!(!text.contains(&encoded), "key material in output");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// One network is never both a plain network and a threshold member's.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_member_admit_on_a_plain_network_row_is_refused() {
    let dstack = FakeDstack::new(APP_ID, INSTANCE_ID);
    let fx = Fixture::new();
    for (name, backend) in [
        ("local", KeyBackendKind::LocalOneOfOne),
        ("dstack", KeyBackendKind::Dstack),
    ] {
        let net = network(name);
        fx.rows.insert(&net, backend);
        let outcome = fx.attest(&dstack, &net.to_string(), &[1; 32], &Admit).await;
        assert!(
            matches!(outcome.result, Err(MemberKeyError::NotThresholdNetwork)),
            "{:?}",
            outcome.result
        );
        assert_eq!(
            outcome.audit.last().unwrap().reason,
            "not-threshold-network"
        );
        assert!(!fx.key_path(&net).exists());
    }
    let net = network("threshold");
    fx.rows.insert(&net, KeyBackendKind::Threshold);
    fx.attest(&dstack, &net.to_string(), &[1; 32], &Admit)
        .await
        .result
        .unwrap();
}

#[tokio::test]
async fn a_plain_create_is_refused_while_a_member_key_record_exists() {
    use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
    let fx = Fixture::new();
    let net = network("default");
    let now = SystemTime::now();
    let ran = AtomicBool::new(false);
    let create = || async { ran.store(true, SeqCst) };

    // No share volume, or no key for N: the create runs.
    guard_plain_create(None, &net, create()).await.unwrap();
    guard_plain_create(Some(&fx.keys), &net, create())
        .await
        .unwrap();
    assert!(ran.swap(false, SeqCst));

    // A pending key, then a held one: refused, and the create never runs.
    fx.admit(&net, now).unwrap();
    for hold in [false, true] {
        if hold {
            fx.holdings.hold(&net);
        }
        let refused = guard_plain_create(Some(&fx.keys), &net, create())
            .await
            .unwrap_err();
        assert!(
            matches!(refused, MemberKeyError::PendingThresholdMember),
            "{refused}"
        );
        assert!(refused.to_string().starts_with("pending_threshold_member"));
        assert!(!ran.load(SeqCst));
    }
    fx.holdings.release(&net);

    // Once the pending key expires, the create runs.
    fx.expire(fx.past_ttl(&net)).unwrap();
    guard_plain_create(Some(&fx.keys), &net, create())
        .await
        .unwrap();
    assert!(ran.swap(false, SeqCst));

    // Likewise once a key is unlinked after its last share.
    let other = network("other");
    fx.admit(&other, now).unwrap();
    fx.unlink(&other).unwrap();
    guard_plain_create(Some(&fx.keys), &other, create())
        .await
        .unwrap();
    assert!(ran.load(SeqCst));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_admission_and_a_plain_create_racing_on_one_network_never_both_win() {
    use tinycloud_core::encryption_network::{CreateNetworkRequest, Threshold};
    let dstack = FakeDstack::new(APP_ID, INSTANCE_ID);
    let fx = Fixture::new();
    let (_dir, _db, service) = admission_shape::encryption_service().await;
    let ctx = MemberAttestation {
        keys: &fx.keys,
        dstack_socket: &dstack.socket,
        holdings: &fx.holdings,
        networks: &service,
    };
    for i in 0..16 {
        let net = owned(i, "race");
        let body = json!({ "nonce": hex::encode([i as u8; 32]) });
        let urn = net.to_string();
        let attest = member_attestation(&ctx, &urn, &body, &Admit);
        let create = guard_plain_create(
            Some(&fx.keys),
            &net,
            service.create_one_of_one_network(CreateNetworkRequest {
                name: "race".into(),
                owner_did: net.owner_did().to_owned(),
                threshold: Threshold::one_of_one(),
            }),
        );
        let (outcome, created) = if i % 2 == 0 {
            tokio::join!(attest, create)
        } else {
            let (created, outcome) = tokio::join!(create, attest);
            (outcome, created)
        };
        match (outcome.result, created) {
            (Ok(_), Err(MemberKeyError::PendingThresholdMember)) => {
                assert!(service.get_network(&net).await.is_err());
            }
            (Err(MemberKeyError::NotThresholdNetwork), Ok(Ok(_))) => {
                assert!(!fx.key_path(&net).exists());
            }
            other => panic!("both or neither won: {other:?}"),
        }
    }
}

#[test]
fn a_record_of_another_instance_is_never_expired_or_unlinked() {
    let fx = Fixture::new();
    let net = network("default");
    let other = LocalIdentity {
        app_id: APP_ID.into(),
        instance_id: "00".repeat(20),
    };
    let dir = fx.key_path(&net).parent().unwrap().to_path_buf();
    record::install_or_load(&dir, KeyRecord::generate(&net.to_string(), &other)).unwrap();

    let late = SystemTime::now() + 2 * PENDING_KEY_TTL;
    assert_eq!(fx.expire(late).unwrap(), Vec::new());
    let err = fx.unlink(&net).unwrap_err();
    assert!(
        matches!(err, MemberKeyError::IdentityMismatch("instance_id")),
        "{err}"
    );
    assert!(fx.key_path(&net).exists());
}

#[test]
fn a_key_installed_after_an_unlink_clears_the_unlinked_marker() {
    let fx = Fixture::new();
    let net = network("default");
    let now = SystemTime::now();
    fx.admit(&net, now).unwrap();
    fx.unlink(&net).unwrap();
    let marker = fx.key_path(&net).with_file_name(record::UNLINKED_FILE);
    assert!(marker.exists());

    fx.admit(&net, now).unwrap();
    assert!(!marker.exists());
    assert!(fx.key_path(&net).exists());
}

#[test]
fn an_oversize_record_is_refused() {
    let fx = Fixture::new();
    let net = network("default");
    fx.admit(&net, SystemTime::now()).unwrap();
    let path = fx.key_path(&net);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.resize(MAX_KEY_RECORD_BYTES + 1, 0);
    std::fs::write(&path, &bytes).unwrap();

    let err = record::read_record(&path).unwrap_err();
    assert!(
        matches!(err, MemberKeyError::MalformedRecord("oversize")),
        "{err}"
    );
    let err = fx.keys.load(&net, &identity()).unwrap_err();
    assert!(
        matches!(err, MemberKeyError::MalformedRecord("oversize")),
        "{err}"
    );
}
