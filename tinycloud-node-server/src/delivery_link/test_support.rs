//! Builds signed share records and short links for tests. Every key here is
//! generated or fixed for the test; nothing protects anything.

use super::*;
use crate::links_fetch::{LinkFetchError, LinkRecordFetcher};
use serde_json::json;
use tinycloud_core::libp2p::identity::{ed25519, Keypair};

pub(crate) const ORIGIN: &str = "https://share.tinycloud.xyz";
pub(crate) const LINK_ID: &str = "lqdw5iopqq2tkkvjj6gbbi5vbv";
/// A fixed TEST key: 43 base64url characters.
pub(crate) const TEST_KEY: [u8; 32] = [0x5a; 32];

pub(crate) fn b64(bytes: &[u8]) -> String {
    encode_config(bytes, URL_SAFE_NO_PAD)
}

pub(crate) fn did_of(keypair: &ed25519::Keypair) -> String {
    tinycloud_core::keys::public_key_to_did_key(Keypair::from(keypair.clone()).public())
}

pub(crate) fn seal(plaintext: &[u8], key: &[u8; 32], nonce: [u8; SEALED_NONCE_BYTES]) -> Vec<u8> {
    let ciphertext = Aes256Gcm::new_from_slice(key)
        .unwrap()
        .encrypt(
            &Nonce::from(nonce),
            AeadPayload {
                msg: plaintext,
                aad: SEALED_AAD,
            },
        )
        .unwrap();
    let mut sealed = vec![SEALED_VERSION];
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    sealed
}

pub(crate) fn header_for(issuer: &str, sealed: &[u8], expires_at: &str) -> Value {
    json!({
        "version": 1,
        "type": "share",
        "issuer": issuer,
        "audience": "https://api.tinycloud.xyz",
        "issuedAt": "2026-10-24T12:00:00.000Z",
        "expiresAt": expires_at,
        "size": sealed.len(),
        "bodyCid": raw_cid(sealed),
        "nonce": b64(&[5; 16]),
    })
}

/// The detached signature of `header` under the links header domain.
pub(crate) fn sign_header(header: &Value, signer: &ed25519::Keypair) -> String {
    let mut signed = LINK_HEADER_DOMAIN.to_vec();
    signed.extend_from_slice(&tinycloud_core::policy_capability::jcs::canonicalize(
        header,
    ));
    b64(&signer.sign(&Sha256::digest(signed)))
}

pub(crate) fn record_header(header: &Value, signature: Option<&str>) -> String {
    let mut record = json!({ "header": header });
    if let Some(signature) = signature {
        record["signature"] = json!({ "algorithm": "Ed25519", "value": signature });
    }
    b64(&tinycloud_core::policy_capability::jcs::canonicalize(
        &record,
    ))
}

pub(crate) fn short_link(origin: &str, id: &str, key: &[u8; 32], cid: &str) -> String {
    format!("{origin}/s/{id}#v=4&k={}&c={cid}", b64(key))
}

pub(crate) struct BuiltLink {
    pub href: String,
    pub header: Value,
    pub sealed: Vec<u8>,
    pub fetched: FetchedLink,
}

/// A valid signed share record for `plaintext`, sealed under `TEST_KEY`, and
/// the link that names it.
pub(crate) fn build(plaintext: &[u8], signer: &ed25519::Keypair, expires_at: &str) -> BuiltLink {
    let sealed = seal(plaintext, &TEST_KEY, [7; SEALED_NONCE_BYTES]);
    let header = header_for(&did_of(signer), &sealed, expires_at);
    let signature = sign_header(&header, signer);
    BuiltLink {
        href: short_link(ORIGIN, LINK_ID, &TEST_KEY, &raw_cid(&sealed)),
        fetched: FetchedLink {
            record_header: record_header(&header, Some(&signature)),
            body: sealed.clone(),
        },
        header,
        sealed,
    }
}

type StubRecords = std::collections::HashMap<String, Result<(String, Vec<u8>), LinkFetchError>>;

/// An in-memory links API: records by id, a fetch counter, and optional
/// failures. The production fetcher is exercised separately against a TLS
/// test server.
#[derive(Default)]
pub(crate) struct StubLinks {
    records: parking_lot::Mutex<StubRecords>,
    pub fetches: std::sync::atomic::AtomicUsize,
}

impl StubLinks {
    pub(crate) fn put(&self, id: &str, built: &BuiltLink) {
        self.records.lock().insert(
            id.to_owned(),
            Ok((
                built.fetched.record_header.clone(),
                built.fetched.body.clone(),
            )),
        );
    }

    pub(crate) fn fail(&self, id: &str, error: LinkFetchError) {
        self.records.lock().insert(id.to_owned(), Err(error));
    }

    pub(crate) fn fetch_count(&self) -> usize {
        self.fetches.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl LinkRecordFetcher for StubLinks {
    async fn fetch(&self, id: &LinkId) -> Result<FetchedLink, LinkFetchError> {
        self.fetches
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match self.records.lock().get(id.as_str()) {
            Some(Ok((record_header, body))) => Ok(FetchedLink {
                record_header: record_header.clone(),
                body: body.clone(),
            }),
            Some(Err(error)) => Err(*error),
            None => Err(LinkFetchError::NotFound),
        }
    }
}

/// `YYYY-MM-DDTHH:mm:ss.SSSZ`, as a link header writes its times.
pub(crate) fn millis(time: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second(),
        time.millisecond()
    )
}
