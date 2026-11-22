//! TC-1791 live check for delegated SQL caveats.
//!
//! Signs as a throwaway wallet that owns one probe space, delegates
//! `tinycloud.sql/read` on that space's `probe1791` database to a throwaway
//! key under each caveat form the release changes, and invokes as that key.
//! Prints one line per step: name, HTTP status, expected status, the refusal
//! code when there is one, and PASS or FAIL. No keys, tokens or bodies.
//!
//! Usage: `tinycloud-caveat-probe <node origin> <state file>`
//! The state file holds the two throwaway keys and is created on the first
//! run, so every later run reuses the same probe space.

use anyhow::{anyhow, bail, Context, Result};
use k256::ecdsa::SigningKey;
use rand::RngCore;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::{collections::HashMap, fs, path::Path, str::FromStr};
use tinycloud_auth::{
    cacaos::{siwe::TimeStamp, siwe_cacao::Signature},
    ipld_core::cid::Cid,
    multihash_codetable::{Code, MultihashDigest},
    resolver::DID_METHODS,
    resource::{Path as ResourcePath, Service, SpaceId},
    siwe_recap::Ability,
    ssi::{
        claims::{chrono, jwt::NumericDate},
        dids::{DIDBuf, DIDURLBuf},
        jwk::JWK,
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_sdk_rs::authorization::InvocationHeaders;
use tinycloud_sdk_wasm::{
    host::{generate_host_siwe_message, siwe_to_delegation_headers, HostConfig, SignedMessage},
    session::{complete_session_setup, prepare_session, Session, SessionConfig, SignedSession},
};

const SPACE_NAME: &str = "caveatprobe";
const DB: &str = "probe1791";
const READ: &str = "tinycloud.sql/read";

struct Reply {
    status: u16,
    body: String,
}

impl Reply {
    /// The refusal code a node error body starts with (`sql_caveat_violation:
    /// table` -> `sql_caveat_violation`), or `-`. Never the rest of the body.
    fn code(&self) -> String {
        let head = self.body.split([':', ' ']).next().unwrap_or_default();
        if !head.is_empty()
            && head.len() <= 64
            && head
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c == '-')
        {
            head.to_string()
        } else {
            "-".to_string()
        }
    }
}

struct Probe {
    http: reqwest::blocking::Client,
    origin: String,
    wallet: SigningKey,
    address: [u8; 20],
    space: SpaceId,
    delegatee: JWK,
    delegatee_vm: String,
    failures: usize,
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

fn load_or_create_state(path: &Path) -> Result<(SigningKey, JWK)> {
    if path.exists() {
        let state: Value = serde_json::from_slice(&fs::read(path)?)?;
        let key = hex::decode(state["wallet"].as_str().context("state: wallet")?)?;
        let wallet = SigningKey::from_slice(&key)?;
        let delegatee: JWK = serde_json::from_value(state["delegatee"].clone())?;
        return Ok((wallet, delegatee));
    }
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let wallet = SigningKey::from_slice(&seed)?;
    let delegatee = JWK::generate_ed25519()?;
    let state = json!({
        "note": "TC-1791 caveat probe: throwaway keys for one probe space only",
        "wallet": hex::encode(wallet.to_bytes()),
        "delegatee": delegatee,
    });
    fs::write(path, serde_json::to_vec_pretty(&state)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok((wallet, delegatee))
}

impl Probe {
    fn new(origin: &str, state: &Path) -> Result<Self> {
        let (wallet, mut delegatee) = load_or_create_state(state)?;
        delegatee.algorithm = Some(tinycloud_auth::ssi::jwk::Algorithm::EdDSA);
        let public = wallet.verifying_key().to_encoded_point(false);
        let hash = Keccak256::digest(&public.as_bytes()[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        let did = format!("did:pkh:eip155:1:{}", checksummed(&address));
        let space = SpaceId::new(
            DIDBuf::from_str(&did).map_err(|e| anyhow!("did: {e}"))?,
            SPACE_NAME
                .to_string()
                .try_into()
                .map_err(|_| anyhow!("space name"))?,
        )
        .map_err(|e| anyhow!("space id: {e}"))?;
        let delegatee_vm = verification_method(&delegatee)?;
        Ok(Self {
            http: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
            origin: origin.trim_end_matches('/').to_string(),
            wallet,
            address,
            space,
            delegatee,
            delegatee_vm,
            failures: 0,
        })
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

    fn post(&self, path: &str, authorization: &str, body: Option<&Value>) -> Result<Reply> {
        let mut request = self
            .http
            .post(format!("{}{path}", self.origin))
            .header("Authorization", authorization);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().with_context(|| format!("POST {path}"))?;
        let status = response.status().as_u16();
        let body = response.text().unwrap_or_default();
        Ok(Reply { status, body })
    }

    fn report(&mut self, step: &str, reply: &Reply, expected: u16, code: Option<&str>) -> bool {
        let ok = reply.status == expected && code.is_none_or(|c| reply.code() == c);
        if !ok {
            self.failures += 1;
        }
        println!(
            "{step} status={} expected={expected}{} code={} {}",
            reply.status,
            code.map(|c| format!(" expected_code={c}"))
                .unwrap_or_default(),
            reply.code(),
            if ok { "PASS" } else { "FAIL" }
        );
        ok
    }

    /// Hosts the space (a repeat on an existing space is reported, not fatal)
    /// and returns the owner session, its delegation stored on the node.
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
            domain: "probe.tinycloud.xyz".parse()?,
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
        println!("setup-host status={} code={}", reply.status, reply.code());

        let mut paths = HashMap::new();
        paths.insert(
            DB.parse::<ResourcePath>()?,
            [
                "tinycloud.sql/read",
                "tinycloud.sql/write",
                "tinycloud.sql/schema",
            ]
            .iter()
            .map(|a| a.parse::<Ability>())
            .collect::<Result<Vec<_>, _>>()?,
        );
        let mut abilities = HashMap::new();
        abilities.insert("sql".parse::<Service>()?, paths);
        let prepared = prepare_session(SessionConfig {
            abilities,
            space_abilities: None,
            raw_abilities: HashMap::new(),
            address: self.address,
            chain_id: 1,
            domain: "probe.tinycloud.xyz".parse()?,
            issued_at,
            space_id: self.space.clone(),
            additional_spaces: None,
            not_before: None,
            expiration_time: timestamp(2 * 3600)?,
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

    fn owner_sql(&mut self, session: &Session, step: &str, body: Value) -> Result<bool> {
        let invocation = session.invoke(
            [(
                "sql".parse::<Service>()?,
                DB.parse::<ResourcePath>()?,
                None,
                None,
                ["tinycloud.sql/write", "tinycloud.sql/schema"]
                    .iter()
                    .map(|a| a.parse::<Ability>())
                    .collect::<Result<Vec<_>, _>>()?,
            )],
            None,
        )?;
        let reply = self.post(
            "/invoke",
            &authorization(InvocationHeaders::new(invocation))?,
            Some(&body),
        )?;
        Ok(self.report(step, &reply, 200, None))
    }

    fn database_uri(&self) -> Result<tinycloud_auth::resource::iri_string::types::UriString> {
        Ok(self
            .space
            .clone()
            .to_resource(
                "sql".parse::<Service>()?,
                Some(DB.parse::<ResourcePath>()?),
                None,
                None,
            )
            .as_uri())
    }

    /// `POST /delegate` of `tinycloud.sql/read` on the probe database from the
    /// owner session to the throwaway key, with `caveats` as the caveat list.
    fn delegate(&self, session: &Session, caveats: Value, proof: Vec<Cid>) -> Result<Reply> {
        let entries: Vec<std::collections::BTreeMap<String, Value>> =
            serde_json::from_value(caveats)?;
        let mut capabilities = Capabilities::<Value>::new();
        capabilities.with_actions(
            self.database_uri()?,
            std::iter::once((READ.parse::<Ability>()?, entries)),
        );
        let token = Payload {
            issuer: session
                .verification_method
                .parse::<DIDURLBuf>()
                .map_err(|e| anyhow!("issuer: {e}"))?,
            audience: did_of(&self.delegatee_vm)
                .parse::<DIDBuf>()
                .map_err(|e| anyhow!("audience: {e}"))?,
            not_before: None,
            expiration: numeric_date(3600)?,
            nonce: Some(format!("urn:uuid:{}", uuid::Uuid::new_v4())),
            facts: Some(Vec::<Value>::new()),
            proof,
            attenuation: capabilities,
        }
        .sign(
            session.jwk.get_algorithm().unwrap_or_default(),
            &session.jwk,
        )?
        .encode()?;
        self.post("/delegate", &token, None)
    }

    fn delegation_cid(reply: &Reply) -> Result<Cid> {
        let json: Value = serde_json::from_str(&reply.body)?;
        Ok(json["cid"]
            .as_str()
            .context("no cid in /delegate reply")?
            .parse::<Cid>()?)
    }

    /// A SQL request signed by the throwaway key under `grant`, claiming
    /// `caveats` (`[{}]` for none; a constrained-statements grant must be
    /// invoked with its own profile).
    fn sql_as_delegatee(&self, grant: Cid, caveats: &Value, body: Value) -> Result<Reply> {
        let entries: Vec<std::collections::BTreeMap<String, Value>> =
            serde_json::from_value(caveats.clone())?;
        let mut capabilities = Capabilities::<Value>::new();
        capabilities.with_actions(
            self.database_uri()?,
            std::iter::once((READ.parse::<Ability>()?, entries)),
        );
        let token = Payload {
            issuer: self
                .delegatee_vm
                .parse::<DIDURLBuf>()
                .map_err(|e| anyhow!("issuer: {e}"))?,
            audience: did_of(&self.delegatee_vm)
                .parse::<DIDBuf>()
                .map_err(|e| anyhow!("audience: {e}"))?,
            not_before: None,
            expiration: numeric_date(120)?,
            nonce: Some(format!("urn:uuid:{}", uuid::Uuid::new_v4())),
            facts: Some(Vec::<Value>::new()),
            proof: vec![grant],
            attenuation: capabilities,
        }
        .sign(
            self.delegatee.get_algorithm().unwrap_or_default(),
            &self.delegatee,
        )?
        .encode()?;
        self.post("/invoke", &token, Some(&body))
    }

    /// Delegates under `caveats` and reports the answer; the grant's CID when
    /// it was admitted.
    fn grant(&mut self, session: &Session, step: &str, caveats: Value) -> Result<Option<Cid>> {
        let reply = self.delegate(session, caveats, vec![session.delegation_cid])?;
        Ok(if self.report(step, &reply, 200, None) {
            Some(Self::delegation_cid(&reply)?)
        } else {
            None
        })
    }

    fn query(sql: &str) -> Value {
        json!({ "action": "query", "sql": sql })
    }

    fn run(&mut self) -> Result<()> {
        let session = self.owner_session()?;
        if !self.owner_sql(
            &session,
            "setup-tables",
            json!({
                "action": "execute",
                "schema": [
                    "CREATE TABLE IF NOT EXISTS p_a(id INTEGER PRIMARY KEY, v TEXT)",
                    "CREATE TABLE IF NOT EXISTS p_b(id INTEGER PRIMARY KEY, v TEXT)",
                ],
                "sql": "INSERT OR IGNORE INTO p_a VALUES (1, 'a')",
            }),
        )? {
            bail!("setup: the probe tables could not be created");
        }

        let none = json!([{}]);

        // (e) the delegated `tables` form: admitted, and enforced at /invoke.
        if let Some(grant) = self.grant(&session, "e-delegate", json!([{ "tables": ["p_a"] }]))? {
            let reply = self.sql_as_delegatee(grant, &none, Self::query("SELECT v FROM p_a"))?;
            self.report("e-select-listed", &reply, 200, None);
            let reply = self.sql_as_delegatee(grant, &none, Self::query("SELECT v FROM p_b"))?;
            self.report(
                "e-select-unlisted",
                &reply,
                403,
                Some("sql_caveat_violation"),
            );
        }

        // (e-reg) `[{}]` stays "no caveats".
        if let Some(grant) = self.grant(&session, "e-reg-delegate", none.clone())? {
            let reply = self.sql_as_delegatee(grant, &none, Self::query("SELECT v FROM p_b"))?;
            self.report("e-reg-select", &reply, 200, None);
        }

        // (e2) the constrained-statements profile.
        let profile = json!([{
            "mode": "constrained-statements",
            "readOnly": true,
            "statements": [{ "name": "n", "sql": "SELECT 1" }],
        }]);
        if let Some(grant) = self.grant(&session, "e2-delegate", profile.clone())? {
            let reply = self.sql_as_delegatee(
                grant,
                &profile,
                json!({ "action": "executeStatement", "name": "n" }),
            )?;
            self.report("e2-named", &reply, 200, None);
            let reply = self.sql_as_delegatee(grant, &profile, Self::query("SELECT 1"))?;
            self.report("e2-raw", &reply, 403, Some("sql-raw-query-blocked"));
        }

        // (g) a parent the node never stored.
        let mut unknown = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut unknown);
        let unknown = Cid::new_v1(0x55, Code::Blake3_256.digest(&unknown));
        let reply = self.delegate(&session, json!([{}]), vec![unknown])?;
        self.report("g-unstored-parent", &reply, 401, None);
        Ok(())
    }
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
        eprintln!("usage: tinycloud-caveat-probe <node origin> <state file>");
        std::process::exit(2);
    }
    let outcome = Probe::new(&args[1], Path::new(&args[2])).and_then(|mut probe| {
        probe.run()?;
        Ok(probe.failures)
    });
    match outcome {
        Ok(0) => println!("result PASS"),
        Ok(failures) => {
            println!("result FAIL failures={failures}");
            std::process::exit(1);
        }
        Err(error) => {
            // Setup errors name the step, never a key or token.
            println!("result ERROR {error}");
            std::process::exit(1);
        }
    }
}
