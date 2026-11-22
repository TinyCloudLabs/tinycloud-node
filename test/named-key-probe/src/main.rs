//! TC-3284 live check for named keys under `secrets/` (#703 semantics).
//!
//! Signs as a throwaway wallet that owns one probe space and its `default`
//! encryption network. It creates the seeded key `secrets/smoke-<ts>`, wraps
//! a random 32-byte content key to it, stores the envelope in KV, reads it
//! back, and has a throwaway did:key decrypt it under an exact-key grant. It
//! then checks the refusals #703 promises and deletes the key; the delete
//! runs whenever the key was created, even after a failed step.
//!
//! Prints one line per step: name, HTTP status, expected status, the refusal
//! code when there is one, and PASS or FAIL. No keys, tokens or bodies.
//!
//! Usage: `tinycloud-named-key-probe <node origin> <state file>`
//! The state file holds the throwaway keys for this run only: it is created
//! with mode 0600 and removed when the run ends, so every run uses a fresh
//! owner, space and network.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use k256::ecdsa::SigningKey;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::Path,
    str::FromStr,
};
use tinycloud_auth::{
    authorization::{HeaderEncode, TinyCloudDelegation},
    cacaos::{
        siwe::{Message, TimeStamp, Version},
        siwe_cacao::{Eip191, Payload as CacaoPayload, Signature},
    },
    ipld_core::cid::Cid,
    resolver::DID_METHODS,
    resource::{Path as ResourcePath, Service, SpaceId},
    siwe_recap::{Ability, Capability as Recap},
    ssi::{
        claims::{chrono, jwt::NumericDate},
        dids::{DIDBuf, DIDURLBuf},
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_sdk_rs::authorization::InvocationHeaders;
use tinycloud_sdk_wasm::{
    host::{generate_host_siwe_message, siwe_to_delegation_headers, HostConfig, SignedMessage},
    session::{complete_session_setup, prepare_session, Session, SessionConfig, SignedSession},
};

const SPACE_NAME: &str = "namedkeyprobe";
const NETWORK_NAME: &str = "default";
const DOMAIN: &str = "probe.tinycloud.xyz";
const FEATURE: &str = "encryption-named-keys-v1";

const DECRYPT: &str = "tinycloud.encryption/decrypt";
const NETWORK_CREATE: &str = "tinycloud.encryption/network.create";
const KEY_CREATE: &str = "tinycloud.encryption/key.create";
const KEY_DELETE: &str = "tinycloud.encryption/key.delete";
const KV_PUT: &str = "tinycloud.kv/put";
const KV_GET: &str = "tinycloud.kv/get";

const NETWORK_ADMIN_TYPE: &str = "tinycloud.encryption.network-admin/v1";
const KEY_ADMIN_TYPE: &str = "tinycloud.encryption.key-admin/v1";
const DECRYPT_TYPE: &str = "tinycloud.encryption.decrypt/v1";
const ALG_V1: &str = "x25519-aes256gcm/v1";
const KEY_DELETE_URI_PREFIX: &str = "urn:tinycloud:encryption:key-delete:";

/// Every delegation the probe issues ends within the hour, and each one
/// ends before its parent, so no refusal is about lifetime: the owner
/// session, then its grants, then the holder's re-delegation.
const SESSION_SECS: i64 = 3000;
const GRANT_SECS: i64 = SESSION_SECS - 300;
const REDELEGATION_SECS: i64 = GRANT_SECS - 300;
/// A v1 wrap's ephemeral public key never starts with the TCW2 magic.
const WRAP_V2_MAGIC: &[u8] = b"TCW2";
/// The first byte of a v1 sealed key (`ColumnEncryption` legacy format).
const SEAL_V1: u8 = 0x01;

struct Reply {
    status: u16,
    body: String,
}

impl Reply {
    /// The refusal code a node error body starts with (`key_exists: ...` ->
    /// `key_exists`), or `-`. Never the rest of the body.
    fn code(&self) -> String {
        let head = self.body.split([':', ' ']).next().unwrap_or_default();
        if !head.is_empty()
            && head.len() <= 64
            && head
                .chars()
                .all(|c| c.is_ascii_alphabetic() || c == '_' || c == '-')
        {
            head.to_string()
        } else {
            "-".to_string()
        }
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

/// A did:key signer: its JWK and verification method.
struct Signer {
    jwk: JWK,
    vm: String,
}

impl Signer {
    fn new(mut jwk: JWK) -> Result<Self> {
        jwk.algorithm = Some(Algorithm::EdDSA);
        let vm = verification_method(&jwk)?;
        Ok(Self { jwk, vm })
    }

    fn did(&self) -> &str {
        did_of(&self.vm)
    }
}

/// One content key wrapped (v1) to a key's public key, and the receiver key
/// that opens the node's re-wrapped answer.
struct Wrapped {
    content_key: [u8; 32],
    wrapped: Vec<u8>,
    receiver: x25519_dalek::StaticSecret,
}

impl Wrapped {
    fn to(public: &[u8]) -> Result<Self> {
        let mut content_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut content_key);
        Ok(Self {
            content_key,
            wrapped: wrap_v1(public, &content_key)?,
            receiver: x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng),
        })
    }

    /// The content key from the node's decrypt answer.
    fn open(&self, answer: &Reply) -> Result<Vec<u8>> {
        let wrapped = base64::decode(
            answer.json()["wrappedKey"]
                .as_str()
                .context("decrypt answer carries no wrappedKey")?,
        )?;
        unwrap_v1(&self.receiver, &wrapped)
    }
}

/// `x25519-aes256gcm/v1`: ephemeral X25519 public key, then the content key
/// sealed with AES-256-GCM under the raw shared secret as
/// `0x01 || nonce || ciphertext || tag`.
fn wrap_v1(public: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let recipient = x25519_dalek::PublicKey::from(
        <[u8; 32]>::try_from(public).map_err(|_| anyhow!("public key is not 32 bytes"))?,
    );
    let (ephemeral, ephemeral_public) = loop {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);
        if !public.as_bytes().starts_with(WRAP_V2_MAGIC) {
            break (secret, public);
        }
    };
    let shared = ephemeral.diffie_hellman(&recipient);
    if !shared.was_contributory() {
        bail!("wrap: non-contributory shared secret");
    }
    let cipher = Aes256Gcm::new_from_slice(shared.as_bytes())?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let sealed = cipher
        .encrypt(&Nonce::from(nonce), plaintext)
        .map_err(|_| anyhow!("wrap: seal failed"))?;
    let mut out = Vec::with_capacity(32 + 1 + 12 + sealed.len());
    out.extend_from_slice(ephemeral_public.as_bytes());
    out.push(SEAL_V1);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn unwrap_v1(receiver: &x25519_dalek::StaticSecret, wrapped: &[u8]) -> Result<Vec<u8>> {
    if wrapped.len() < 32 + 1 + 12 + 16 || wrapped[32] != SEAL_V1 {
        bail!("unwrap: not a v1 wrap");
    }
    let ephemeral = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(&wrapped[..32])?);
    let shared = receiver.diffie_hellman(&ephemeral);
    let cipher = Aes256Gcm::new_from_slice(shared.as_bytes())?;
    cipher
        .decrypt(&Nonce::from(<[u8; 12]>::try_from(&wrapped[33..45])?), &wrapped[45..])
        .map_err(|_| anyhow!("unwrap: open failed"))
}

/// The node's canonical JSON hash: SHA-256 hex of the value with object keys
/// sorted and no whitespace.
fn canonical_hash(value: &Value) -> String {
    fn write(value: &Value, out: &mut String) {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push('{');
                for (i, key) in keys.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&Value::String(key.clone()).to_string());
                    out.push(':');
                    write(&map[key], out);
                }
                out.push('}');
            }
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(item, out);
                }
                out.push(']');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let mut out = String::new();
    write(value, &mut out);
    hex::encode(Sha256::digest(out.as_bytes()))
}

fn verification_method(jwk: &JWK) -> Result<String> {
    let mut vm = DID_METHODS.generate(jwk, "key")?.to_string();
    let fragment = vm
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("did:key has no fragment"))?
        .1
        .to_string();
    vm.push('#');
    vm.push_str(&fragment);
    Ok(vm)
}

fn did_of(vm: &str) -> &str {
    vm.split('#').next().unwrap_or_default()
}

fn timestamp(offset_secs: i64) -> Result<TimeStamp> {
    let at = chrono::Utc::now() + chrono::Duration::seconds(offset_secs);
    TimeStamp::from_str(&at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .map_err(|e| anyhow!("timestamp: {e}"))
}

fn numeric_date(offset_secs: i64) -> Result<NumericDate> {
    Ok(NumericDate::try_from_seconds(
        (chrono::Utc::now().timestamp() + offset_secs) as f64,
    )?)
}

/// EIP-55 mixed-case spelling of `address`, as a SIWE message carries it.
fn checksummed(address: &[u8; 20]) -> String {
    let lower = hex::encode(address);
    let hash = Keccak256::digest(lower.as_bytes());
    let mixed: String = lower
        .chars()
        .enumerate()
        .map(|(i, c)| {
            let nibble = (hash[i / 2] >> if i % 2 == 0 { 4 } else { 0 }) & 0x0f;
            if nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    format!("0x{mixed}")
}

/// The `Authorization` value of a serialized `{Delegation,Invocation}Headers`.
fn authorization(headers: impl serde::Serialize) -> Result<String> {
    serde_json::to_value(headers)?["Authorization"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("headers carry no Authorization"))
}

/// The state file of this run. Dropping it removes the file, so the keys
/// outlive no run: not after an early return, not after a panic.
struct StateFile<'a>(&'a Path);

impl Drop for StateFile<'_> {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(self.0) {
            println!("state file not removed: {}", error.kind());
        }
    }
}

/// Creates the state file with mode 0600 in one step (`create_new`, so two
/// concurrent runs cannot share it), holding this run's throwaway wallet and
/// delegatee key. A file left by an interrupted run is refused: remove it.
/// The returned guard removes the file; it exists from the moment the file
/// does.
fn create_state(path: &Path) -> Result<(StateFile<'_>, SigningKey, JWK)> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("create state file (a leftover from an earlier run must be removed)")?;
    let guard = StateFile(path);
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let wallet = SigningKey::from_slice(&seed)?;
    let delegatee = JWK::generate_ed25519()?;
    let state = json!({
        "note": "TC-3284 named-key probe: throwaway keys for one run; removed when it ends",
        "wallet": hex::encode(wallet.to_bytes()),
        "delegatee": delegatee,
    });
    std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(&state)?)?;
    file.sync_all()?;
    Ok((guard, wallet, delegatee))
}

/// Only `https`, or plain `http` to this machine: a typo must never send an
/// `Authorization` header in cleartext.
fn origin_allowed(origin: &str) -> bool {
    let origin = origin.trim_end_matches('/');
    origin.starts_with("https://")
        || ["http://localhost", "http://127.0.0.1", "http://[::1]"]
            .iter()
            .any(|local| {
                origin
                    .strip_prefix(local)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
            })
}

struct Probe {
    http: reqwest::blocking::Client,
    origin: String,
    wallet: SigningKey,
    address: [u8; 20],
    owner: String,
    space: SpaceId,
    network: String,
    node: String,
    delegatee: Signer,
    failures: usize,
}

impl Probe {
    fn new(origin: &str, wallet: SigningKey, delegatee: JWK) -> Result<Self> {
        let public = wallet.verifying_key().to_encoded_point(false);
        let hash = Keccak256::digest(&public.as_bytes()[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        let owner = format!("did:pkh:eip155:1:{}", checksummed(&address));
        // Public, throwaway and probe-owned: recorded in the deploy log.
        println!("probe-owner address={}", checksummed(&address));
        let space = SpaceId::new(
            DIDBuf::from_str(&owner).map_err(|e| anyhow!("did: {e}"))?,
            SPACE_NAME
                .to_string()
                .try_into()
                .map_err(|_| anyhow!("space name"))?,
        )
        .map_err(|e| anyhow!("space id: {e}"))?;
        Ok(Self {
            http: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
            origin: origin.trim_end_matches('/').to_string(),
            wallet,
            address,
            network: format!("urn:tinycloud:encryption:{owner}:{NETWORK_NAME}"),
            owner,
            space,
            node: String::new(),
            delegatee: Signer::new(delegatee)?,
            failures: 0,
        })
    }

    fn key(&self, path: &str) -> String {
        format!("{}/{path}", self.network)
    }

    /// EIP-191 `personal_sign` with the recovery byte as 27/28.
    fn personal_sign(&self, message: &str) -> Result<Signature> {
        let mut digest = Keccak256::new();
        digest.update(format!("\x19Ethereum Signed Message:\n{}", message.len()));
        digest.update(message.as_bytes());
        let (signature, recovery) = self.wallet.sign_digest_recoverable(digest)?;
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&signature.to_bytes());
        bytes[64] = 27 + recovery.to_byte();
        Ok(Signature::from(bytes))
    }

    fn send(&self, request: reqwest::blocking::RequestBuilder, what: &str) -> Result<Reply> {
        let response = request.send().with_context(|| what.to_string())?;
        let status = response.status().as_u16();
        let body = response.text().unwrap_or_default();
        Ok(Reply { status, body })
    }

    fn get(&self, path: &str, authorization: Option<&str>) -> Result<Reply> {
        let mut request = self.http.get(format!("{}{path}", self.origin));
        if let Some(authorization) = authorization {
            request = request.header("Authorization", authorization);
        }
        self.send(request, "GET")
    }

    fn post(&self, path: &str, authorization: &str, body: Option<&Value>) -> Result<Reply> {
        let mut request = self
            .http
            .post(format!("{}{path}", self.origin))
            .header("Authorization", authorization);
        if let Some(body) = body {
            request = request.json(body);
        }
        self.send(request, "POST")
    }

    fn line(&mut self, step: &str, reply: &Reply, expected: &str, ok: bool) -> bool {
        if !ok {
            self.failures += 1;
        }
        println!(
            "{step} status={} expected={expected} code={} {}",
            reply.status,
            reply.code(),
            if ok { "PASS" } else { "FAIL" }
        );
        ok
    }

    /// Reports `reply` against one expected status and, when given, the
    /// refusal code its body must start with.
    fn report(&mut self, step: &str, reply: &Reply, expected: u16, code: Option<&str>) -> bool {
        let ok = reply.status == expected && code.is_none_or(|c| reply.code() == c);
        let expected = match code {
            Some(code) => format!("{expected} expected_code={code}"),
            None => expected.to_string(),
        };
        self.line(step, reply, &expected, ok)
    }

    /// A UCAN from `signer` to `audience` with one capability per entry.
    #[allow(clippy::too_many_arguments)]
    fn ucan(
        jwk: &JWK,
        vm: &str,
        audience: &str,
        caps: &[(&str, &str)],
        facts: Vec<Value>,
        proof: Vec<Cid>,
        lifetime_secs: i64,
    ) -> Result<String> {
        let mut attenuation = Capabilities::<Value>::new();
        for (resource, ability) in caps {
            attenuation.with_action(
                resource.parse()?,
                ability.parse::<Ability>()?,
                [BTreeMap::<String, Value>::new()],
            );
        }
        Ok(Payload {
            issuer: vm
                .parse::<DIDURLBuf>()
                .map_err(|e| anyhow!("issuer: {e}"))?,
            audience: audience
                .parse::<DIDBuf>()
                .map_err(|e| anyhow!("audience: {e}"))?,
            not_before: Some(numeric_date(0)?),
            expiration: numeric_date(lifetime_secs)?,
            nonce: Some(format!("urn:uuid:{}", uuid::Uuid::new_v4())),
            facts: Some(facts),
            proof,
            attenuation,
        }
        .sign(jwk.get_algorithm().unwrap_or_default(), jwk)?
        .encode()?)
    }

    /// An invocation to the node by the owner session.
    fn owner_invocation(
        &self,
        session: &Session,
        resource: &str,
        ability: &str,
        facts: Value,
    ) -> Result<String> {
        Self::ucan(
            &session.jwk,
            &session.verification_method,
            &self.node,
            &[(resource, ability)],
            vec![facts],
            vec![session.delegation_cid],
            60,
        )
    }

    /// Hosts the space and returns the owner session, its SIWE delegation
    /// stored on the node: KV on the probe space, `network.create` and
    /// `decrypt` on the network, `key.create` and `decrypt` on `secrets/`.
    fn owner_session(&mut self) -> Result<Session> {
        let peer = self
            .http
            .get(format!(
                "{}/peer/generate/{}",
                self.origin,
                urlencode(&self.space.to_string())
            ))
            .send()?;
        let peer_status = peer.status().as_u16();
        let peer_id = peer.text()?;
        if peer_status != 200 {
            bail!("setup: /peer/generate answered {peer_status}");
        }
        let issued_at = timestamp(-60)?;
        let message = generate_host_siwe_message(HostConfig {
            address: self.address,
            chain_id: 1,
            domain: DOMAIN.parse()?,
            issued_at: issued_at.clone(),
            space_id: self.space.clone(),
            peer_id,
        })?;
        let signature = self.personal_sign(&message.to_string())?;
        let host = siwe_to_delegation_headers(SignedMessage {
            siwe: message,
            signature,
        });
        let reply = self.post("/delegate", &authorization(host)?, None)?;
        if !self.report("setup-host", &reply, 200, None) {
            bail!("setup: the probe space was not hosted");
        }

        let mut paths = HashMap::new();
        paths.insert(
            "".parse::<ResourcePath>()?,
            vec![KV_PUT.parse::<Ability>()?, KV_GET.parse::<Ability>()?],
        );
        let mut abilities = HashMap::new();
        abilities.insert("kv".parse::<Service>()?, paths);
        let mut raw_abilities = HashMap::new();
        raw_abilities.insert(
            self.network.clone(),
            vec![NETWORK_CREATE.parse()?, DECRYPT.parse()?],
        );
        raw_abilities.insert(
            format!("{}/secrets/", self.network),
            vec![KEY_CREATE.parse()?, DECRYPT.parse()?],
        );
        let prepared = prepare_session(SessionConfig {
            abilities,
            space_abilities: None,
            raw_abilities,
            address: self.address,
            chain_id: 1,
            domain: DOMAIN.parse()?,
            issued_at,
            space_id: self.space.clone(),
            additional_spaces: None,
            not_before: None,
            expiration_time: timestamp(SESSION_SECS)?,
            parents: None,
            jwk: None,
            delegate_uri: None,
            nonce: None,
            invocation_ttl_secs: None,
        })?;
        let signature = self.personal_sign(&prepared.siwe.to_string())?;
        let session = complete_session_setup(SignedSession {
            session: prepared,
            signature,
        })?;
        let reply = self.post(
            "/delegate",
            &authorization(session.delegation_header.clone())?,
            None,
        )?;
        if !self.report("setup-session", &reply, 200, None) {
            bail!("setup: the owner session was not admitted");
        }
        Ok(session)
    }

    /// The owner's network: created when it is missing, reused otherwise.
    fn ensure_network(&mut self, session: &Session) -> Result<bool> {
        let reply = self.get(&format!("/encryption/networks/{}", self.network), None)?;
        if reply.status == 200 {
            return Ok(self.report("s2-network-exists", &reply, 200, None));
        }
        let body = json!({ "name": NETWORK_NAME, "ownerDid": self.owner });
        let auth = self.owner_invocation(
            session,
            &self.network,
            NETWORK_CREATE,
            json!({
                "type": NETWORK_ADMIN_TYPE,
                "targetNode": self.node,
                "networkId": self.network,
                "action": NETWORK_CREATE,
                "bodyHash": canonical_hash(&body),
            }),
        )?;
        let reply = self.post("/encryption/networks", &auth, Some(&body))?;
        Ok(self.report("s2-network-create", &reply, 200, None))
    }

    /// The owner's `key.create` of `path`, the capability on the exact key.
    fn create_key(&self, session: &Session, path: &str, deletable: bool) -> Result<Reply> {
        let body = json!({ "keyPath": path, "deletable": deletable });
        let auth = self.owner_invocation(
            session,
            &self.key(path),
            KEY_CREATE,
            json!({
                "type": KEY_ADMIN_TYPE,
                "targetNode": self.node,
                "networkId": self.network,
                "keyPath": path,
                "action": KEY_CREATE,
                "bodyHash": canonical_hash(&body),
            }),
        )?;
        self.post(
            &format!("/encryption/networks/{}/keys", self.network),
            &auth,
            Some(&body),
        )
    }

    /// `POST /delegate` of `decrypt` on `resource` from the owner session to
    /// `audience`; the grant's CID when it was admitted.
    fn owner_grant(
        &mut self,
        session: &Session,
        step: &str,
        resource: &str,
        audience: &str,
    ) -> Result<Option<Cid>> {
        let token = Self::ucan(
            &session.jwk,
            &session.verification_method,
            audience,
            &[(resource, DECRYPT)],
            Vec::new(),
            vec![session.delegation_cid],
            GRANT_SECS,
        )?;
        let reply = self.post("/delegate", &token, None)?;
        Ok(if self.report(step, &reply, 200, None) {
            Some(delegation_cid(&reply)?)
        } else {
            None
        })
    }

    /// A decrypt over `/invoke` by the delegatee under `grant`: the capability
    /// names `cap_path` (`None`: the bare network), the body and facts name
    /// `body_path` (`None`: no `keyPath`).
    fn decrypt(
        &self,
        grant: Cid,
        cap_path: Option<&str>,
        body_path: Option<&str>,
        key_version: u64,
        case: &Wrapped,
    ) -> Result<Reply> {
        let encrypted = base64::encode(&case.wrapped);
        let receiver = base64::encode(x25519_dalek::PublicKey::from(&case.receiver).as_bytes());
        let encrypted_hash = canonical_hash(&Value::String(encrypted.clone()));
        let receiver_hash = canonical_hash(&Value::String(receiver.clone()));
        let mut body = json!({
            "type": DECRYPT_TYPE,
            "targetNode": self.node,
            "networkId": self.network,
            "alg": ALG_V1,
            "keyVersion": key_version,
            "encryptedSymmetricKey": encrypted,
            "encryptedSymmetricKeyHash": encrypted_hash,
            "receiverPublicKey": receiver,
            "receiverPublicKeyHash": receiver_hash,
        });
        if let Some(path) = body_path {
            body["keyPath"] = json!(path);
        }
        let mut facts = json!({
            "type": DECRYPT_TYPE,
            "targetNode": self.node,
            "networkId": self.network,
            "bodyHash": canonical_hash(&body),
            "encryptedSymmetricKeyHash": encrypted_hash,
            "receiverPublicKeyHash": receiver_hash,
            "alg": ALG_V1,
            "keyVersion": key_version,
        });
        if let Some(path) = body_path {
            facts["keyPath"] = json!(path);
        }
        let resource = match cap_path {
            Some(path) => self.key(path),
            None => self.network.clone(),
        };
        let auth = Self::ucan(
            &self.delegatee.jwk,
            &self.delegatee.vm,
            &self.node,
            &[(&resource, DECRYPT)],
            vec![facts],
            vec![grant],
            30,
        )?;
        self.post("/invoke", &auth, Some(&body))
    }

    fn kv(&self, session: &Session, path: &str, ability: &str) -> Result<String> {
        let invocation = session.invoke(
            [(
                "kv".parse::<Service>()?,
                path.parse::<ResourcePath>()?,
                None,
                None,
                [ability.parse::<Ability>()?],
            )],
            None,
        )?;
        authorization(InvocationHeaders::new(invocation))
    }

    /// The owner's SIWE delete credential for one key, per
    /// `docs/encryption-named-keys.md`: ReCap `{ <key URN>: [key.delete] }`,
    /// uri `urn:tinycloud:encryption:key-delete:<node DID>`, statement
    /// `Delete the TinyCloud key <key URN>.`, at most 300 s.
    fn delete_key(&self, path: &str) -> Result<Reply> {
        let urn = self.key(path);
        let mut recap = Recap::<Value>::default();
        recap
            .with_action_convert(
                urn.as_str(),
                KEY_DELETE,
                Vec::<BTreeMap<String, Value>>::new(),
            )
            .map_err(|e| anyhow!("delete recap: {e}"))?;
        let message = recap
            .build_message(Message {
                scheme: None,
                domain: DOMAIN.parse()?,
                address: self.address,
                statement: Some(format!("Delete the TinyCloud key {urn}.")),
                uri: format!("{KEY_DELETE_URI_PREFIX}{}", self.node).parse()?,
                version: Version::V1,
                chain_id: 1,
                nonce: format!("nkprobe{}", uuid::Uuid::new_v4().simple()),
                issued_at: timestamp(0)?,
                expiration_time: Some(timestamp(240)?),
                not_before: None,
                request_id: None,
                resources: Vec::new(),
            })
            .map_err(|e| anyhow!("delete message: {e}"))?;
        let signature = self.personal_sign(&message.to_string())?;
        let cacao = CacaoPayload::from(message).sign::<Eip191>(signature);
        let header = TinyCloudDelegation::Cacao(Box::new(cacao))
            .encode()
            .map_err(|e| anyhow!("delete credential: {e}"))?;
        self.post(
            &format!("/encryption/networks/{}/key-actions/delete", self.network),
            &header,
            Some(&json!({ "keyPath": path })),
        )
    }

    fn run(&mut self) -> Result<()> {
        // 1. The feature is advertised.
        let reply = self.get("/info", None)?;
        let info = reply.json();
        let advertised = info["features"]
            .as_array()
            .is_some_and(|f| f.iter().any(|f| f == FEATURE));
        let ok = reply.status == 200 && advertised;
        self.line("s1-info-feature", &reply, &format!("200 feature={FEATURE}"), ok);
        if !ok {
            bail!("the node does not advertise {FEATURE}; nothing else is checked");
        }
        self.node = info["nodeId"]
            .as_str()
            .context("/info carries no nodeId")?
            .to_string();

        // 2. The network, then the seeded key.
        let session = self.owner_session()?;
        if !self.ensure_network(&session)? {
            bail!("setup: the probe network is missing");
        }
        let ts = chrono::Utc::now().timestamp();
        let smoke = format!("secrets/smoke-{ts}");
        let reply = self.create_key(&session, &smoke, true)?;
        let created = reply.json();
        let public = created["publicEncryptionKey"]
            .as_str()
            .and_then(|k| base64::decode(k).ok());
        let ok = reply.status == 200 && created["kind"] == "deletable" && public.is_some();
        self.line("s2-create", &reply, "200 kind=deletable publicKey", ok);
        if reply.status != 200 {
            bail!("the smoke key was not created; nothing else is checked");
        }
        let key_version = created["keyVersion"].as_u64().unwrap_or(1);

        // Steps 3 to 6b; step 7 deletes the key whatever they answered.
        let outcome = public
            .context("the create answer carries no public key")
            .and_then(|public| self.with_key(&session, ts, &smoke, &public, key_version));

        // 7. Delete, then the old version is refused.
        let reply = self.delete_key(&smoke)?;
        let ok = reply.status == 200 && reply.json()["count"] == 1;
        self.line("s7-delete", &reply, "200 count=1", ok);
        if let Ok(Some((grant, case))) = &outcome {
            let reply = self.decrypt(*grant, Some(&smoke), Some(&smoke), key_version, case)?;
            self.report("s7-decrypt-deleted", &reply, 403, Some("key_deleted"));
        } else {
            self.failures += 1;
            println!("s7-decrypt-deleted skipped: no exact grant FAIL");
        }
        outcome.map(|_| ())
    }

    /// Steps 3 to 6b. Returns the delegatee's exact grant and the stored
    /// wrap for step 7.
    fn with_key(
        &mut self,
        session: &Session,
        ts: i64,
        smoke: &str,
        public: &[u8],
        key_version: u64,
    ) -> Result<Option<(Cid, Wrapped)>> {
        let reply = self.create_key(session, smoke, true)?;
        self.report("s2-create-again", &reply, 409, Some("key_exists"));
        let sibling = format!("{smoke}-x");
        let reply = self.create_key(session, &sibling, false)?;
        self.report("s2-create-nondeletable", &reply, 400, Some("key_path_invalid"));

        // 3. The unauthenticated public GET never answers under `secrets/`.
        let reply = self.get(
            &format!("/encryption/networks/{}/keys/{smoke}", self.network),
            None,
        )?;
        self.report("s3-public-get", &reply, 404, Some("key_not_found"));

        // 4. put: the envelope, wrapped to the key, in the probe space.
        let case = Wrapped::to(public)?;
        let encrypted = base64::encode(&case.wrapped);
        let envelope = json!({
            "v": 2,
            "networkId": self.network,
            "keyPath": smoke,
            "alg": ALG_V1,
            "keyVersion": key_version,
            "encryptedSymmetricKey": encrypted,
            "encryptedSymmetricKeyHash": canonical_hash(&Value::String(encrypted.clone())),
        });
        let kv_path = format!("named-key-probe/{ts}");
        let auth = self.kv(session, &kv_path, KV_PUT)?;
        let reply = self.send(
            self.http
                .post(format!("{}/invoke", self.origin))
                .header("Authorization", auth)
                .header("Content-Type", "application/json")
                .body(envelope.to_string()),
            "KV put",
        )?;
        self.report("s4-kv-put", &reply, 200, None);

        // 5. get: the envelope back, decrypted by the delegatee under an
        // exact-key grant.
        let auth = self.kv(session, &kv_path, KV_GET)?;
        let reply = self.send(
            self.http
                .post(format!("{}/invoke", self.origin))
                .header("Authorization", auth),
            "KV get",
        )?;
        let stored = reply.json();
        let ok = reply.status == 200 && stored == envelope;
        self.line("s5-kv-get", &reply, "200 envelope=same", ok);
        let stored_wrap = stored["encryptedSymmetricKey"]
            .as_str()
            .and_then(|w| base64::decode(w).ok())
            .unwrap_or_default();
        let case = Wrapped {
            wrapped: stored_wrap,
            ..case
        };

        let holder = self.delegatee.did().to_string();
        let Some(grant) = self.owner_grant(session, "s5-delegate-exact", &self.key(smoke), &holder)?
        else {
            return Ok(None);
        };
        let reply = self.decrypt(grant, Some(smoke), Some(smoke), key_version, &case)?;
        if self.report("s5-decrypt", &reply, 200, None) {
            let opened = case.open(&reply).ok();
            let ok = opened.as_deref() == Some(&case.content_key[..]);
            self.line("s5-unwrap-equal", &reply, "32 bytes equal", ok);
        }

        // 6. A bare-network grant opens no secret key's wrap.
        let network = self.network.clone();
        if let Some(bare) = self.owner_grant(session, "s6-delegate-network", &network, &holder)? {
            let reply = self.decrypt(bare, None, None, key_version, &case)?;
            self.report("s6-network-decrypt", &reply, 403, Some("key_unwrap_failed"));
        }

        // 6b(i). An exact grant on the sibling opens nothing of this key.
        if let Some(other) =
            self.owner_grant(session, "s6b-delegate-sibling", &self.key(&sibling), &holder)?
        {
            let reply = self.decrypt(other, Some(smoke), Some(smoke), key_version, &case)?;
            let ok = matches!(reply.status, 401 | 403) && !reply.body.contains("wrappedKey");
            self.line("s6b-sibling-decrypt", &reply, "403|401", ok);
        }

        // 6b(ii). The exact grant's holder can't widen it to `secrets/`. The
        // same re-delegation on the exact key is admitted, so the refusal is
        // about the prefix alone.
        let second = Signer::new(JWK::generate_ed25519()?)?;
        let exact = self.key(smoke);
        let prefix = format!("{}/secrets/", self.network);
        for (step, resource, expected) in [
            ("s6b-redelegate-exact", &exact, 200),
            ("s6b-redelegate-prefix", &prefix, 401),
        ] {
            let token = Self::ucan(
                &self.delegatee.jwk,
                &self.delegatee.vm,
                second.did(),
                &[(resource, DECRYPT)],
                Vec::new(),
                vec![grant],
                REDELEGATION_SECS,
            )?;
            let reply = self.post("/delegate", &token, None)?;
            self.report(step, &reply, expected, None);
        }
        Ok(Some((grant, case)))
    }
}

fn delegation_cid(reply: &Reply) -> Result<Cid> {
    Ok(reply.json()["cid"]
        .as_str()
        .context("no cid in /delegate reply")?
        .parse::<Cid>()?)
}

fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: tinycloud-named-key-probe <node origin> <state file>");
        std::process::exit(2);
    }
    if !origin_allowed(&args[1]) {
        eprintln!("refused origin: use https://, or http:// to localhost, 127.0.0.1 or [::1]");
        std::process::exit(2);
    }
    let state = Path::new(&args[2]);
    let outcome = create_state(state).and_then(|(_guard, wallet, delegatee)| {
        // `_guard` drops when this closure returns and removes the file.
        Probe::new(&args[1], wallet, delegatee).map(|mut probe| {
            if let Err(error) = probe.run() {
                // Errors name the step, never a key or token.
                println!("stopped: {error}");
                probe.failures = probe.failures.max(1);
            }
            probe.failures
        })
    });
    match outcome {
        Ok(0) => println!("result PASS"),
        Ok(failures) => {
            println!("result FAIL failures={failures}");
            std::process::exit(1);
        }
        Err(error) => {
            println!("result ERROR {error}");
            std::process::exit(1);
        }
    }
}
