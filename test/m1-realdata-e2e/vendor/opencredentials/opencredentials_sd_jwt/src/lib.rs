use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{
    ed25519::signature::{Signer, Verifier},
    Keypair, PublicKey, Signature,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

const SD_ALG: &str = "sha-256";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JWK {
    pub params: Params,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Params {
    OKP(OkpParams),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OkpParams {
    pub public_key: JwkBytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<JwkBytes>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JwkBytes(pub Vec<u8>);

impl JWK {
    pub fn generate_ed25519() -> Result<Self, SdJwtError> {
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let secret = ed25519_dalek::SecretKey::from_bytes(&secret_bytes)
            .map_err(|e| SdJwtError::Signing(e.to_string()))?;
        let public = PublicKey::from(&secret);

        Ok(Self {
            params: Params::OKP(OkpParams {
                public_key: JwkBytes(public.to_bytes().to_vec()),
                private_key: Some(JwkBytes(secret_bytes.to_vec())),
            }),
        })
    }
}

#[derive(Debug, Error)]
pub enum SdJwtError {
    #[error("invalid SD-JWT: {0}")]
    InvalidFormat(String),
    #[error("invalid disclosure: {0}")]
    InvalidDisclosure(String),
    #[error("unsupported disclosure type: {0}")]
    UnsupportedDisclosure(String),
    #[error("signing failed: {0}")]
    Signing(String),
    #[error("verification failed: {0}")]
    Verification(String),
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub trait CompactSigner {
    fn algorithm(&self) -> &'static str {
        "EdDSA"
    }

    fn sign(&self, signing_input: &str) -> Result<Vec<u8>, SdJwtError>;
}

pub trait CompactVerifier {
    fn algorithm(&self) -> &'static str {
        "EdDSA"
    }

    fn verify(&self, signing_input: &str, signature: &[u8]) -> Result<(), SdJwtError>;
}

pub struct Ed25519Signer {
    keypair: Keypair,
}

impl Ed25519Signer {
    pub fn from_keypair_bytes(secret_key: &[u8], public_key: &[u8]) -> Result<Self, SdJwtError> {
        let secret = ed25519_dalek::SecretKey::from_bytes(secret_key)
            .map_err(|e| SdJwtError::Signing(e.to_string()))?;
        let public = PublicKey::from_bytes(public_key)
            .map_err(|e| SdJwtError::Signing(e.to_string()))?;

        Ok(Self {
            keypair: Keypair { secret, public },
        })
    }

    pub fn from_jwk(jwk: &JWK) -> Result<Self, SdJwtError> {
        let Params::OKP(okp) = &jwk.params;
        let private_key = okp
            .private_key
            .as_ref()
            .ok_or_else(|| SdJwtError::Signing("missing private key in Ed25519 JWK".to_string()))?;
        Self::from_keypair_bytes(&private_key.0, &okp.public_key.0)
    }
}

impl CompactSigner for Ed25519Signer {
    fn sign(&self, signing_input: &str) -> Result<Vec<u8>, SdJwtError> {
        Ok(self
            .keypair
            .sign(signing_input.as_bytes())
            .to_bytes()
            .to_vec())
    }
}

#[derive(Clone)]
pub struct Ed25519Verifier {
    public_key: PublicKey,
}

impl Ed25519Verifier {
    pub fn from_public_key_bytes(public_key: &[u8]) -> Result<Self, SdJwtError> {
        Ok(Self {
            public_key: PublicKey::from_bytes(public_key)
                .map_err(|e| SdJwtError::Verification(e.to_string()))?,
        })
    }

    pub fn from_jwk(jwk: &JWK) -> Result<Self, SdJwtError> {
        let Params::OKP(okp) = &jwk.params;
        Self::from_public_key_bytes(&okp.public_key.0)
    }
}

impl CompactVerifier for Ed25519Verifier {
    fn verify(&self, signing_input: &str, signature: &[u8]) -> Result<(), SdJwtError> {
        let signature = Signature::from_bytes(signature)
            .map_err(|e| SdJwtError::Verification(e.to_string()))?;
        self.public_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|e| SdJwtError::Verification(e.to_string()))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ParsedDisclosure {
    pub disclosure: String,
    pub digest: String,
    pub path: Option<String>,
    pub claim_name: Option<String>,
    pub value: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ParsedSdJwt {
    pub issuer_jwt: String,
    pub payload: Value,
    pub disclosures: Vec<ParsedDisclosure>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedSdJwt {
    pub issuer: String,
    pub subject: String,
    pub vct: String,
    pub payload: Value,
    pub disclosed_claims: Value,
    pub disclosed_paths: Vec<String>,
    pub undisclosed_paths: Vec<String>,
}

pub fn issue_sd_jwt(
    payload: &Value,
    conceal_paths: &[String],
    signer: &impl CompactSigner,
) -> Result<String, SdJwtError> {
    let mut payload = payload.clone();
    if let Value::Object(obj) = &mut payload {
        obj.insert("_sd_alg".to_string(), Value::String(SD_ALG.to_string()));
    }

    let mut disclosures = Vec::new();
    for path in conceal_paths {
        let disclosure = conceal_claim(&mut payload, path)?;
        disclosures.push(disclosure);
    }

    sort_sd_arrays(&mut payload);

    let issuer_jwt = sign_compact_jwt(&payload, signer)?;
    let mut result = issuer_jwt;
    result.push('~');
    if !disclosures.is_empty() {
        result.push_str(&disclosures.join("~"));
        result.push('~');
    }
    Ok(result)
}

pub fn present_sd_jwt(
    issued_sd_jwt: &str,
    disclose_paths: &[String],
) -> Result<String, SdJwtError> {
    let parsed = parse_sd_jwt(issued_sd_jwt)?;
    let mut result = parsed.issuer_jwt;
    result.push('~');

    let selected = parsed
        .disclosures
        .into_iter()
        .filter(|disclosure| {
            disclosure
                .path
                .as_ref()
                .map(|path| disclose_paths.contains(path))
                .unwrap_or(false)
        })
        .map(|disclosure| disclosure.disclosure)
        .collect::<Vec<_>>();

    if !selected.is_empty() {
        result.push_str(&selected.join("~"));
        result.push('~');
    }

    Ok(result)
}

pub fn parse_sd_jwt(input: &str) -> Result<ParsedSdJwt, SdJwtError> {
    let parts = input.split('~').collect::<Vec<_>>();
    if parts.is_empty() || parts[0].is_empty() {
        return Err(SdJwtError::InvalidFormat(
            "missing issuer-signed JWT".to_string(),
        ));
    }

    let issuer_jwt = parts[0].to_string();
    let payload = decode_jwt_payload(&issuer_jwt)?;

    let mut disclosures = Vec::new();
    for disclosure in parts.into_iter().skip(1).filter(|part| !part.is_empty()) {
        disclosures.push(parse_disclosure(disclosure)?);
    }

    assign_disclosure_paths(&payload, &mut disclosures, "");

    Ok(ParsedSdJwt {
        issuer_jwt,
        payload,
        disclosures,
    })
}

pub fn verify_sd_jwt(
    input: &str,
    verifier: &impl CompactVerifier,
) -> Result<VerifiedSdJwt, SdJwtError> {
    let parsed = parse_sd_jwt(input)?;
    verify_compact_jwt(&parsed.issuer_jwt, verifier)?;

    let mut materialized = parsed.payload.clone();
    let mut disclosed_paths = Vec::new();
    for disclosure in &parsed.disclosures {
        apply_disclosure(&mut materialized, disclosure)?;
        if let Some(path) = &disclosure.path {
            disclosed_paths.push(path.clone());
        }
    }

    cleanup_sd_metadata(&mut materialized);

    let issuer = materialized
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| SdJwtError::Verification("missing issuer".to_string()))?
        .to_string();
    let subject = materialized
        .get("sub")
        .and_then(Value::as_str)
        .ok_or_else(|| SdJwtError::Verification("missing subject".to_string()))?
        .to_string();
    let vct = materialized
        .get("vct")
        .and_then(Value::as_str)
        .ok_or_else(|| SdJwtError::Verification("missing vct".to_string()))?
        .to_string();

    let undisclosed_paths = opencredentials_disclosable_paths(&vct)
        .unwrap_or_default()
        .into_iter()
        .filter(|path| !disclosed_paths.contains(path))
        .collect::<Vec<_>>();

    Ok(VerifiedSdJwt {
        issuer,
        subject,
        vct,
        payload: parsed.payload,
        disclosed_claims: materialized,
        disclosed_paths,
        undisclosed_paths,
    })
}

pub fn opencredentials_disclosable_paths(vct: &str) -> Option<Vec<String>> {
    let paths = match vct {
        "https://spec.opencredentials.xyz/credentials/github-verification/v1" => {
            vec!["/github/profile_url", "/github/gist_id"]
        }
        "https://spec.opencredentials.xyz/credentials/email-verification/v1" => {
            vec!["/email/address"]
        }
        "opencredentials.email/v1" => vec!["/email", "/emailDomain"],
        "https://spec.opencredentials.xyz/credentials/twitter-verification/v1" => {
            vec!["/twitter/profile_url", "/twitter/post_id"]
        }
        "https://spec.opencredentials.xyz/credentials/reddit-verification/v1" => {
            vec!["/reddit/profile_url"]
        }
        "https://spec.opencredentials.xyz/credentials/soundcloud-verification/v1" => {
            vec!["/soundcloud/profile_url"]
        }
        "https://spec.opencredentials.xyz/credentials/dns-verification/v1" => Vec::new(),
        "https://spec.opencredentials.xyz/credentials/poap-ownership-verification/v1" => Vec::new(),
        "https://spec.opencredentials.xyz/credentials/same-controller-assertion/v1" => Vec::new(),
        _ => return None,
    };

    Some(paths.into_iter().map(|path| path.to_string()).collect())
}

fn parse_disclosure(disclosure: &str) -> Result<ParsedDisclosure, SdJwtError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(disclosure)
        .map_err(|e| SdJwtError::InvalidDisclosure(e.to_string()))?;
    let value: Value = serde_json::from_slice(&bytes)?;
    let array = value.as_array().ok_or_else(|| {
        SdJwtError::InvalidDisclosure("disclosure must decode to a JSON array".to_string())
    })?;

    let (claim_name, claim_value) = match array.as_slice() {
        [_, Value::String(claim_name), claim_value] => {
            (Some(claim_name.clone()), claim_value.clone())
        }
        [_, claim_value] => (None, claim_value.clone()),
        _ => {
            return Err(SdJwtError::InvalidDisclosure(
                "unsupported disclosure element count".to_string(),
            ))
        }
    };

    Ok(ParsedDisclosure {
        disclosure: disclosure.to_string(),
        digest: disclosure_digest(disclosure),
        path: None,
        claim_name,
        value: claim_value,
    })
}

fn decode_jwt_payload(jwt: &str) -> Result<Value, SdJwtError> {
    let parts = jwt.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(SdJwtError::InvalidFormat(
            "compact JWT must have 3 segments".to_string(),
        ));
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| SdJwtError::InvalidFormat(e.to_string()))?;
    Ok(serde_json::from_slice(&payload_bytes)?)
}

fn sign_compact_jwt(payload: &Value, signer: &impl CompactSigner) -> Result<String, SdJwtError> {
    let header = json!({ "alg": signer.algorithm() });
    let encoded_header = encode_json(&header)?;
    let encoded_payload = encode_json(payload)?;
    let signing_input = format!("{}.{}", encoded_header, encoded_payload);
    let signature = signer.sign(&signing_input)?;
    let encoded_signature = URL_SAFE_NO_PAD.encode(signature);
    Ok(format!("{}.{}", signing_input, encoded_signature))
}

fn verify_compact_jwt(jwt: &str, verifier: &impl CompactVerifier) -> Result<(), SdJwtError> {
    let parts = jwt.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(SdJwtError::InvalidFormat(
            "compact JWT must have 3 segments".to_string(),
        ));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| SdJwtError::InvalidFormat(e.to_string()))?;
    let header: Value = serde_json::from_slice(&header_bytes)?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| SdJwtError::InvalidFormat("missing alg header".to_string()))?;
    if alg != verifier.algorithm() {
        return Err(SdJwtError::Verification(format!(
            "unsupported JWT alg `{}`",
            alg
        )));
    }

    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| SdJwtError::InvalidFormat(e.to_string()))?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verifier.verify(&signing_input, &signature)
}

fn conceal_claim(payload: &mut Value, path: &str) -> Result<String, SdJwtError> {
    let tokens = parse_pointer(path)?;
    if tokens.is_empty() {
        return Err(SdJwtError::UnsupportedDisclosure(
            "root concealment is not supported".to_string(),
        ));
    }

    let claim_name = tokens.last().unwrap().clone();
    let parent_tokens = &tokens[..tokens.len() - 1];

    let parent = value_at_tokens_mut(payload, parent_tokens)?;
    let parent_map = parent.as_object_mut().ok_or_else(|| {
        SdJwtError::UnsupportedDisclosure(
            "only object property disclosures are supported".to_string(),
        )
    })?;

    let claim_value = parent_map
        .remove(&claim_name)
        .ok_or_else(|| SdJwtError::InvalidDisclosure(format!("no claim found at `{}`", path)))?;

    let disclosure = make_object_disclosure(&claim_name, &claim_value)?;
    let digest = disclosure_digest(&disclosure);

    let sd_entry = parent_map
        .entry("_sd".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let sd_array = sd_entry.as_array_mut().ok_or_else(|| {
        SdJwtError::InvalidDisclosure("existing _sd entry is not an array".to_string())
    })?;
    sd_array.push(Value::String(digest));

    Ok(disclosure)
}

fn apply_disclosure(payload: &mut Value, disclosure: &ParsedDisclosure) -> Result<(), SdJwtError> {
    let path = disclosure.path.as_ref().ok_or_else(|| {
        SdJwtError::Verification("disclosure could not be mapped to a claim path".to_string())
    })?;
    let tokens = parse_pointer(path)?;
    if tokens.is_empty() {
        return Err(SdJwtError::Verification(
            "disclosure path cannot point to the root".to_string(),
        ));
    }
    let claim_name = tokens.last().unwrap().clone();
    let parent_tokens = &tokens[..tokens.len() - 1];
    let parent = value_at_tokens_mut(payload, parent_tokens)?;
    let parent_map = parent.as_object_mut().ok_or_else(|| {
        SdJwtError::Verification("disclosure parent is not an object".to_string())
    })?;
    let sd_array = parent_map
        .get_mut("_sd")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| SdJwtError::Verification("missing _sd array for disclosure".to_string()))?;

    let Some(index) = sd_array
        .iter()
        .position(|value| value.as_str() == Some(disclosure.digest.as_str()))
    else {
        return Err(SdJwtError::Verification(format!(
            "disclosure digest for `{}` not found in payload",
            path
        )));
    };

    sd_array.remove(index);
    parent_map.insert(claim_name, disclosure.value.clone());
    Ok(())
}

fn assign_disclosure_paths(
    payload: &Value,
    disclosures: &mut [ParsedDisclosure],
    current_path: &str,
) {
    let Some(object) = payload.as_object() else {
        return;
    };

    if let Some(sd_array) = object.get("_sd").and_then(Value::as_array) {
        for digest in sd_array.iter().filter_map(Value::as_str) {
            if let Some(disclosure) = disclosures.iter_mut().find(|candidate| {
                candidate.digest == digest
                    && candidate.path.is_none()
                    && candidate.claim_name.is_some()
            }) {
                if let Some(claim_name) = &disclosure.claim_name {
                    disclosure.path = Some(join_pointer(current_path, claim_name));
                }
            }
        }
    }

    for (key, value) in object {
        if key == "_sd" || key == "_sd_alg" {
            continue;
        }
        assign_disclosure_paths(value, disclosures, &join_pointer(current_path, key));
    }
}

fn cleanup_sd_metadata(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.remove("_sd_alg");
            if object
                .get("_sd")
                .and_then(Value::as_array)
                .map(|items| items.is_empty())
                .unwrap_or(false)
            {
                object.remove("_sd");
            }
            for child in object.values_mut() {
                cleanup_sd_metadata(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                cleanup_sd_metadata(item);
            }
        }
        _ => {}
    }
}

fn sort_sd_arrays(value: &mut Value) {
    match value {
        Value::Object(object) => {
            if let Some(sd_array) = object.get_mut("_sd").and_then(Value::as_array_mut) {
                sd_array.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
            }
            for child in object.values_mut() {
                sort_sd_arrays(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                sort_sd_arrays(item);
            }
        }
        _ => {}
    }
}

fn make_object_disclosure(claim_name: &str, claim_value: &Value) -> Result<String, SdJwtError> {
    let disclosure = Value::Array(vec![
        Value::String(random_salt()),
        Value::String(claim_name.to_string()),
        claim_value.clone(),
    ]);
    encode_json(&disclosure)
}

fn random_salt() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn disclosure_digest(disclosure: &str) -> String {
    let digest = Sha256::digest(disclosure.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn encode_json(value: &Value) -> Result<String, SdJwtError> {
    let bytes = serde_json::to_vec(value)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn parse_pointer(pointer: &str) -> Result<Vec<String>, SdJwtError> {
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    if !pointer.starts_with('/') {
        return Err(SdJwtError::InvalidFormat(format!(
            "JSON pointer `{}` must start with `/`",
            pointer
        )));
    }

    Ok(pointer
        .split('/')
        .skip(1)
        .map(|token| token.replace("~1", "/").replace("~0", "~"))
        .collect())
}

fn value_at_tokens_mut<'a>(
    value: &'a mut Value,
    tokens: &[String],
) -> Result<&'a mut Value, SdJwtError> {
    let mut cursor = value;
    for token in tokens {
        cursor = match cursor {
            Value::Object(map) => map.get_mut(token).ok_or_else(|| {
                SdJwtError::InvalidFormat(format!("missing object key `{}`", token))
            })?,
            Value::Array(items) => {
                let index = token.parse::<usize>().map_err(|_| {
                    SdJwtError::UnsupportedDisclosure(
                        "array traversal is not supported for SD-JWT issuance".to_string(),
                    )
                })?;
                items.get_mut(index).ok_or_else(|| {
                    SdJwtError::InvalidFormat(format!("missing array index `{}`", index))
                })?
            }
            _ => {
                return Err(SdJwtError::InvalidFormat(
                    "cannot traverse through a primitive value".to_string(),
                ))
            }
        };
    }
    Ok(cursor)
}

fn join_pointer(parent: &str, token: &str) -> String {
    let escaped = token.replace('~', "~0").replace('/', "~1");
    if parent.is_empty() {
        format!("/{}", escaped)
    } else {
        format!("{}/{}", parent, escaped)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        issue_sd_jwt, opencredentials_disclosable_paths, present_sd_jwt, verify_sd_jwt,
        Ed25519Signer, Ed25519Verifier, SdJwtError, JWK,
    };
    use serde_json::json;

    fn github_payload() -> serde_json::Value {
        json!({
            "iss": "did:web:issuer.opencredentials.xyz",
            "sub": "did:pkh:eip155:1:0x1234",
            "iat": 1770000000,
            "nbf": 1770000000,
            "exp": 1801536000,
            "jti": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "vct": "https://spec.opencredentials.xyz/credentials/github-verification/v1",
            "github": {
                "username": "sam",
                "profile_url": "https://github.com/sam",
                "gist_id": "abc123def456"
            }
        })
    }

    fn github_concealable_paths() -> Vec<String> {
        vec![
            "/github/profile_url".to_string(),
            "/github/gist_id".to_string(),
        ]
    }

    #[test]
    fn issues_presents_and_verifies_sd_jwt() {
        let jwk = JWK::generate_ed25519().expect("ed25519 jwk");
        let signer = Ed25519Signer::from_jwk(&jwk).expect("signer");
        let verifier = Ed25519Verifier::from_jwk(&jwk).expect("verifier");

        let issued = issue_sd_jwt(&github_payload(), &github_concealable_paths(), &signer)
            .expect("issued sd-jwt");
        let presented =
            present_sd_jwt(&issued, &["/github/profile_url".to_string()]).expect("presentation");
        let verified = verify_sd_jwt(&presented, &verifier).expect("verified sd-jwt");

        assert_eq!(verified.issuer, "did:web:issuer.opencredentials.xyz");
        assert_eq!(verified.subject, "did:pkh:eip155:1:0x1234");
        assert_eq!(
            verified.vct,
            "https://spec.opencredentials.xyz/credentials/github-verification/v1"
        );
        assert_eq!(
            verified.disclosed_paths,
            vec!["/github/profile_url".to_string()]
        );
        assert_eq!(
            verified.undisclosed_paths,
            vec!["/github/gist_id".to_string()]
        );
        assert_eq!(
            verified.disclosed_claims["github"]["username"],
            json!("sam")
        );
        assert_eq!(
            verified.disclosed_claims["github"]["profile_url"],
            json!("https://github.com/sam")
        );
        assert!(verified.disclosed_claims["github"].get("gist_id").is_none());
    }

    #[test]
    fn verifies_fully_disclosed_issued_token() {
        let jwk = JWK::generate_ed25519().expect("ed25519 jwk");
        let signer = Ed25519Signer::from_jwk(&jwk).expect("signer");
        let verifier = Ed25519Verifier::from_jwk(&jwk).expect("verifier");

        let issued = issue_sd_jwt(&github_payload(), &github_concealable_paths(), &signer)
            .expect("issued sd-jwt");
        let verified = verify_sd_jwt(&issued, &verifier).expect("verified issued sd-jwt");

        let mut disclosed_paths = verified.disclosed_paths.clone();
        disclosed_paths.sort();
        assert_eq!(
            disclosed_paths,
            vec![
                "/github/gist_id".to_string(),
                "/github/profile_url".to_string(),
            ]
        );
        assert!(verified.undisclosed_paths.is_empty());
        assert_eq!(
            verified.disclosed_claims["github"]["gist_id"],
            json!("abc123def456")
        );
    }

    #[test]
    fn rejects_wrong_verifier() {
        let issuer_jwk = JWK::generate_ed25519().expect("issuer jwk");
        let verifier_jwk = JWK::generate_ed25519().expect("verifier jwk");
        let signer = Ed25519Signer::from_jwk(&issuer_jwk).expect("signer");
        let wrong_verifier = Ed25519Verifier::from_jwk(&verifier_jwk).expect("verifier");

        let issued = issue_sd_jwt(&github_payload(), &github_concealable_paths(), &signer)
            .expect("issued sd-jwt");
        let error = verify_sd_jwt(&issued, &wrong_verifier).expect_err("verification must fail");

        match error {
            SdJwtError::Verification(_) => {}
            other => panic!("expected verification error, got {other:?}"),
        }
    }

    #[test]
    fn exposes_registry_paths_for_supported_vcts() {
        assert_eq!(
            opencredentials_disclosable_paths(
                "https://spec.opencredentials.xyz/credentials/github-verification/v1"
            ),
            Some(vec![
                "/github/profile_url".to_string(),
                "/github/gist_id".to_string(),
            ])
        );
        assert_eq!(
            opencredentials_disclosable_paths(
                "https://spec.opencredentials.xyz/credentials/dns-verification/v1"
            ),
            Some(Vec::new())
        );
        assert!(opencredentials_disclosable_paths("https://example.com/unknown").is_none());
    }
}
