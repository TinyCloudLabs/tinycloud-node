use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use opencredentials_sd_jwt::{
    issue_sd_jwt, present_sd_jwt, verify_sd_jwt, Ed25519Signer, Ed25519Verifier, SdJwtError,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use thiserror::Error;

pub use opencredentials_sd_jwt::JWK;

pub const EMAIL_VCT: &str = "opencredentials.email/v1";
pub const EMAIL_CLAIM: &str = "email";
pub const EMAIL_DOMAIN_CLAIM: &str = "emailDomain";
pub const EMAIL_DISCLOSURE_PATH: &str = "/email";
pub const EMAIL_DOMAIN_DISCLOSURE_PATH: &str = "/emailDomain";
pub const DEFAULT_TTL_SECONDS: u64 = 365 * 24 * 60 * 60;

#[derive(Debug, Error)]
pub enum OpenCredentialsVerifyError {
    #[error("invalid email: {0}")]
    InvalidEmail(String),
    #[error("invalid email domain: {0}")]
    InvalidEmailDomain(String),
    #[error("ttl must be greater than zero")]
    InvalidTtl,
    #[error("timestamp overflow")]
    TimestampOverflow,
    #[error("system clock is before the Unix epoch")]
    ClockBeforeUnixEpoch,
    #[error("invalid compact JWT: {0}")]
    InvalidJwt(String),
    #[error("unsupported JWT alg `{0}`")]
    UnsupportedAlgorithm(String),
    #[error("SD-JWT error: {0}")]
    SdJwt(#[from] SdJwtError),
    #[error("unsupported vct `{actual}`")]
    UnsupportedVct { actual: String },
    #[error("issuer `{actual}` is not accepted")]
    BadIssuer { actual: String },
    #[error("holder DID mismatch: expected `{expected}`, got `{actual}`")]
    HolderMismatch { expected: String, actual: String },
    #[error("credential expired at {expires_at}, verification time was {now}")]
    Expired { expires_at: i64, now: i64 },
    #[error("credential is not valid before {not_before}, verification time was {now}")]
    NotYetValid { not_before: i64, now: i64 },
    #[error("missing required claim `{0}`")]
    MissingClaim(&'static str),
    #[error("claim `{0}` has the wrong type")]
    InvalidClaim(&'static str),
    #[error("missing required disclosure `{0}`")]
    MissingDisclosure(&'static str),
    #[error("email domain `{actual}` is not allowed")]
    WrongEmailDomain { actual: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EmailCredentialRequest {
    pub holder_did: String,
    pub email: String,
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_id: Option<String>,
}

impl EmailCredentialRequest {
    pub fn new(holder_did: impl Into<String>, email: impl Into<String>) -> Self {
        Self {
            holder_did: holder_did.into(),
            email: email.into(),
            ttl_seconds: DEFAULT_TTL_SECONDS,
            issued_at: None,
            jwt_id: None,
        }
    }

    pub fn with_ttl_seconds(mut self, ttl_seconds: u64) -> Self {
        self.ttl_seconds = ttl_seconds;
        self
    }

    pub fn with_issued_at(mut self, issued_at: i64) -> Self {
        self.issued_at = Some(issued_at);
        self
    }

    pub fn with_jwt_id(mut self, jwt_id: impl Into<String>) -> Self {
        self.jwt_id = Some(jwt_id.into());
        self
    }
}

pub struct EmailCredentialIssuer {
    issuer_did: String,
    signer: Ed25519Signer,
}

impl EmailCredentialIssuer {
    pub fn new_ed25519(issuer_did: impl Into<String>, jwk: &JWK) -> Result<Self> {
        Ok(Self {
            issuer_did: issuer_did.into(),
            signer: Ed25519Signer::from_jwk(jwk)?,
        })
    }

    pub fn issue(&self, request: EmailCredentialRequest) -> Result<String> {
        if request.ttl_seconds == 0 {
            return Err(OpenCredentialsVerifyError::InvalidTtl);
        }

        let email_domain = email_domain_from_address(&request.email)?;
        let issued_at = match request.issued_at {
            Some(value) => value,
            None => current_unix_timestamp()?,
        };
        let ttl = i64::try_from(request.ttl_seconds)
            .map_err(|_| OpenCredentialsVerifyError::TimestampOverflow)?;
        let expires_at = issued_at
            .checked_add(ttl)
            .ok_or(OpenCredentialsVerifyError::TimestampOverflow)?;

        let mut payload = Map::new();
        payload.insert("iss".to_string(), json!(self.issuer_did));
        payload.insert("sub".to_string(), json!(request.holder_did));
        payload.insert("iat".to_string(), json!(issued_at));
        payload.insert("nbf".to_string(), json!(issued_at));
        payload.insert("exp".to_string(), json!(expires_at));
        payload.insert("vct".to_string(), json!(EMAIL_VCT));
        payload.insert(EMAIL_CLAIM.to_string(), json!(request.email));
        payload.insert(EMAIL_DOMAIN_CLAIM.to_string(), json!(email_domain));
        if let Some(jwt_id) = request.jwt_id {
            payload.insert("jti".to_string(), json!(jwt_id));
        }

        issue_sd_jwt(
            &Value::Object(payload),
            &[
                EMAIL_DISCLOSURE_PATH.to_string(),
                EMAIL_DOMAIN_DISCLOSURE_PATH.to_string(),
            ],
            &self.signer,
        )
        .map_err(Into::into)
    }
}

pub struct EmailCredentialVerifier {
    verifier: Ed25519Verifier,
}

impl EmailCredentialVerifier {
    pub fn new_ed25519(jwk: &JWK) -> Result<Self> {
        Ok(Self {
            verifier: Ed25519Verifier::from_jwk(jwk)?,
        })
    }

    pub fn verify(
        &self,
        presentation: &str,
        options: &EmailVerificationOptions,
    ) -> Result<VerifiedEmailCredential> {
        reject_unsupported_alg(presentation)?;

        let verified = verify_sd_jwt(presentation, &self.verifier)?;
        if verified.vct != EMAIL_VCT {
            return Err(OpenCredentialsVerifyError::UnsupportedVct {
                actual: verified.vct,
            });
        }

        if !options.accepted_issuers.is_empty()
            && !options
                .accepted_issuers
                .iter()
                .any(|issuer| issuer == &verified.issuer)
        {
            return Err(OpenCredentialsVerifyError::BadIssuer {
                actual: verified.issuer,
            });
        }

        if let Some(expected) = &options.expected_holder_did {
            if expected != &verified.subject {
                return Err(OpenCredentialsVerifyError::HolderMismatch {
                    expected: expected.clone(),
                    actual: verified.subject,
                });
            }
        }

        let issued_at = required_i64(&verified.disclosed_claims, "iat")?;
        let not_before = optional_i64(&verified.disclosed_claims, "nbf")?;
        let expires_at = required_i64(&verified.disclosed_claims, "exp")?;
        let now = match options.now {
            Some(value) => value,
            None => current_unix_timestamp()?,
        };

        if let Some(not_before) = not_before {
            if now < not_before {
                return Err(OpenCredentialsVerifyError::NotYetValid { not_before, now });
            }
        }
        if now >= expires_at {
            return Err(OpenCredentialsVerifyError::Expired { expires_at, now });
        }

        let email = optional_string(&verified.disclosed_claims, EMAIL_CLAIM)?;
        let email_domain = optional_string(&verified.disclosed_claims, EMAIL_DOMAIN_CLAIM)?;
        let require_email_domain =
            options.require_email_domain || !options.allowed_email_domains.is_empty();
        let normalized_email_domain = match email_domain {
            Some(value) => Some(normalize_email_domain(&value)?),
            None if require_email_domain => {
                return Err(OpenCredentialsVerifyError::MissingDisclosure(
                    EMAIL_DOMAIN_CLAIM,
                ))
            }
            None => None,
        };

        if let Some(email) = &email {
            let derived_domain = email_domain_from_address(email)?;
            if let Some(email_domain) = &normalized_email_domain {
                if &derived_domain != email_domain {
                    return Err(OpenCredentialsVerifyError::InvalidEmailDomain(format!(
                        "email domain `{derived_domain}` does not match disclosed `{email_domain}`"
                    )));
                }
            }
        }

        let allowed_domains = normalize_domain_set(&options.allowed_email_domains)?;
        if let Some(email_domain) = &normalized_email_domain {
            if !allowed_domains.is_empty() && !allowed_domains.contains(email_domain) {
                return Err(OpenCredentialsVerifyError::WrongEmailDomain {
                    actual: email_domain.clone(),
                });
            }
        }

        Ok(VerifiedEmailCredential {
            issuer: verified.issuer,
            holder_did: verified.subject,
            vct: EMAIL_VCT.to_string(),
            email,
            email_domain: normalized_email_domain,
            issued_at,
            not_before,
            expires_at,
            disclosed_paths: verified.disclosed_paths,
            undisclosed_paths: email_undisclosed_paths(presentation)?,
            payload: verified.payload,
            disclosed_claims: verified.disclosed_claims,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct EmailVerificationOptions {
    #[serde(default)]
    pub accepted_issuers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_holder_did: Option<String>,
    #[serde(default)]
    pub allowed_email_domains: Vec<String>,
    #[serde(default)]
    pub require_email_domain: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<i64>,
}

impl EmailVerificationOptions {
    pub fn domain_gate(
        accepted_issuers: impl IntoIterator<Item = impl Into<String>>,
        expected_holder_did: impl Into<String>,
        allowed_email_domains: impl IntoIterator<Item = impl Into<String>>,
        now: i64,
    ) -> Self {
        Self {
            accepted_issuers: accepted_issuers.into_iter().map(Into::into).collect(),
            expected_holder_did: Some(expected_holder_did.into()),
            allowed_email_domains: allowed_email_domains.into_iter().map(Into::into).collect(),
            require_email_domain: true,
            now: Some(now),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedEmailCredential {
    pub issuer: String,
    pub holder_did: String,
    pub vct: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_domain: Option<String>,
    pub issued_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<i64>,
    pub expires_at: i64,
    pub disclosed_paths: Vec<String>,
    pub undisclosed_paths: Vec<String>,
    pub payload: Value,
    pub disclosed_claims: Value,
}

pub type Result<T> = std::result::Result<T, OpenCredentialsVerifyError>;

pub fn issue_email_sd_jwt(
    issuer_did: impl Into<String>,
    issuer_jwk: &JWK,
    request: EmailCredentialRequest,
) -> Result<String> {
    EmailCredentialIssuer::new_ed25519(issuer_did, issuer_jwk)?.issue(request)
}

pub fn present_email_domain(issued_sd_jwt: &str) -> Result<String> {
    present_sd_jwt(issued_sd_jwt, &[EMAIL_DOMAIN_DISCLOSURE_PATH.to_string()]).map_err(Into::into)
}

pub fn present_email(issued_sd_jwt: &str) -> Result<String> {
    present_sd_jwt(issued_sd_jwt, &[EMAIL_DISCLOSURE_PATH.to_string()]).map_err(Into::into)
}

pub fn present_email_and_domain(issued_sd_jwt: &str) -> Result<String> {
    present_sd_jwt(
        issued_sd_jwt,
        &[
            EMAIL_DISCLOSURE_PATH.to_string(),
            EMAIL_DOMAIN_DISCLOSURE_PATH.to_string(),
        ],
    )
    .map_err(Into::into)
}

pub fn normalize_email_domain(domain: &str) -> Result<String> {
    if domain.is_empty() {
        return Err(OpenCredentialsVerifyError::InvalidEmailDomain(
            "domain is empty".to_string(),
        ));
    }
    if !domain.is_ascii() {
        return Err(OpenCredentialsVerifyError::InvalidEmailDomain(
            "domain must be ASCII".to_string(),
        ));
    }
    if domain.len() > 253 {
        return Err(OpenCredentialsVerifyError::InvalidEmailDomain(
            "domain is too long".to_string(),
        ));
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return Err(OpenCredentialsVerifyError::InvalidEmailDomain(
            "domain has empty labels".to_string(),
        ));
    }

    let normalized = domain.to_ascii_lowercase();
    for label in normalized.split('.') {
        if label.is_empty() {
            return Err(OpenCredentialsVerifyError::InvalidEmailDomain(
                "domain has empty labels".to_string(),
            ));
        }
        if label.len() > 63 {
            return Err(OpenCredentialsVerifyError::InvalidEmailDomain(
                "domain label is too long".to_string(),
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(OpenCredentialsVerifyError::InvalidEmailDomain(
                "domain label cannot start or end with hyphen".to_string(),
            ));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(OpenCredentialsVerifyError::InvalidEmailDomain(
                "domain contains invalid characters".to_string(),
            ));
        }
    }

    Ok(normalized)
}

pub fn email_domain_from_address(email: &str) -> Result<String> {
    let parts = email.split('@').collect::<Vec<_>>();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(OpenCredentialsVerifyError::InvalidEmail(
            "expected exactly one @ with non-empty local and domain parts".to_string(),
        ));
    }
    normalize_email_domain(parts[1])
}

fn default_ttl_seconds() -> u64 {
    DEFAULT_TTL_SECONDS
}

fn current_unix_timestamp() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OpenCredentialsVerifyError::ClockBeforeUnixEpoch)?;
    i64::try_from(duration.as_secs()).map_err(|_| OpenCredentialsVerifyError::TimestampOverflow)
}

fn reject_unsupported_alg(sd_jwt: &str) -> Result<()> {
    let issuer_jwt = sd_jwt
        .split('~')
        .next()
        .ok_or_else(|| OpenCredentialsVerifyError::InvalidJwt("missing issuer JWT".to_string()))?;
    let header = issuer_jwt
        .split('.')
        .next()
        .ok_or_else(|| OpenCredentialsVerifyError::InvalidJwt("missing JWT header".to_string()))?;
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|e| OpenCredentialsVerifyError::InvalidJwt(e.to_string()))?;
    let header_value: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| OpenCredentialsVerifyError::InvalidJwt(e.to_string()))?;
    let alg = header_value
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| OpenCredentialsVerifyError::InvalidJwt("missing alg header".to_string()))?;
    if alg != "EdDSA" {
        return Err(OpenCredentialsVerifyError::UnsupportedAlgorithm(
            alg.to_string(),
        ));
    }
    Ok(())
}

fn required_i64(value: &Value, claim: &'static str) -> Result<i64> {
    value
        .get(claim)
        .ok_or(OpenCredentialsVerifyError::MissingClaim(claim))
        .and_then(|value| {
            value
                .as_i64()
                .ok_or(OpenCredentialsVerifyError::InvalidClaim(claim))
        })
}

fn optional_i64(value: &Value, claim: &'static str) -> Result<Option<i64>> {
    value
        .get(claim)
        .map(|value| {
            value
                .as_i64()
                .ok_or(OpenCredentialsVerifyError::InvalidClaim(claim))
        })
        .transpose()
}

fn optional_string(value: &Value, claim: &'static str) -> Result<Option<String>> {
    value
        .get(claim)
        .map(|value| {
            value
                .as_str()
                .map(ToString::to_string)
                .ok_or(OpenCredentialsVerifyError::InvalidClaim(claim))
        })
        .transpose()
}

fn normalize_domain_set(domains: &[String]) -> Result<BTreeSet<String>> {
    domains
        .iter()
        .map(|domain| normalize_email_domain(domain))
        .collect()
}

fn email_undisclosed_paths(presentation: &str) -> Result<Vec<String>> {
    let parsed = opencredentials_sd_jwt::parse_sd_jwt(presentation)?;
    let disclosed = parsed
        .disclosures
        .into_iter()
        .filter_map(|disclosure| disclosure.path)
        .collect::<BTreeSet<_>>();

    Ok([EMAIL_DISCLOSURE_PATH, EMAIL_DOMAIN_DISCLOSURE_PATH]
        .into_iter()
        .filter(|path| !disclosed.contains(*path))
        .map(ToString::to_string)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opencredentials_sd_jwt::parse_sd_jwt;
    use serde_json::json;

    const ISSUER: &str = "did:web:issuer.credentials.org";
    const HOLDER: &str = "did:key:z6Mkholder";
    const ISSUED_AT: i64 = 1_800_000_000;

    fn issuer_and_verifier() -> (EmailCredentialIssuer, EmailCredentialVerifier) {
        let jwk = JWK::generate_ed25519().expect("ed25519 jwk");
        (
            EmailCredentialIssuer::new_ed25519(ISSUER, &jwk).expect("issuer"),
            EmailCredentialVerifier::new_ed25519(&jwk).expect("verifier"),
        )
    }

    fn request(email: &str) -> EmailCredentialRequest {
        EmailCredentialRequest::new(HOLDER, email)
            .with_issued_at(ISSUED_AT)
            .with_ttl_seconds(3600)
            .with_jwt_id("urn:uuid:11111111-1111-1111-1111-111111111111")
    }

    fn domain_gate(now: i64) -> EmailVerificationOptions {
        EmailVerificationOptions::domain_gate([ISSUER], HOLDER, ["tinycloud.xyz"], now)
    }

    #[test]
    fn issues_presents_email_domain_only_and_verifies() {
        let (issuer, verifier) = issuer_and_verifier();

        let issued = issuer
            .issue(request("Sam@TinyCloud.XYZ"))
            .expect("email sd-jwt");
        let presentation = present_email_domain(&issued).expect("domain presentation");
        let parsed = parse_sd_jwt(&presentation).expect("parsed presentation");

        assert_eq!(parsed.disclosures.len(), 1);
        assert_eq!(
            parsed.disclosures[0].path.as_deref(),
            Some(EMAIL_DOMAIN_DISCLOSURE_PATH)
        );

        let verified = verifier
            .verify(&presentation, &domain_gate(ISSUED_AT + 1))
            .expect("verified presentation");

        assert_eq!(verified.issuer, ISSUER);
        assert_eq!(verified.holder_did, HOLDER);
        assert_eq!(verified.vct, EMAIL_VCT);
        assert_eq!(verified.email, None);
        assert_eq!(verified.email_domain.as_deref(), Some("tinycloud.xyz"));
        assert_eq!(verified.issued_at, ISSUED_AT);
        assert_eq!(verified.expires_at, ISSUED_AT + 3600);
        assert_eq!(
            verified.disclosed_paths,
            vec![EMAIL_DOMAIN_DISCLOSURE_PATH.to_string()]
        );
        assert_eq!(
            verified.undisclosed_paths,
            vec![EMAIL_DISCLOSURE_PATH.to_string()]
        );
    }

    #[test]
    fn default_ttl_is_365_days() {
        let request = EmailCredentialRequest::new(HOLDER, "sam@tinycloud.xyz");
        assert_eq!(request.ttl_seconds, DEFAULT_TTL_SECONDS);
    }

    #[test]
    fn rejects_bad_issuer() {
        let jwk = JWK::generate_ed25519().expect("ed25519 jwk");
        let issuer = EmailCredentialIssuer::new_ed25519("did:web:issuer.bad", &jwk).unwrap();
        let verifier = EmailCredentialVerifier::new_ed25519(&jwk).unwrap();
        let presentation =
            present_email_domain(&issuer.issue(request("sam@tinycloud.xyz")).unwrap())
                .expect("presentation");

        let error = verifier
            .verify(&presentation, &domain_gate(ISSUED_AT + 1))
            .expect_err("bad issuer must fail");

        assert!(matches!(
            error,
            OpenCredentialsVerifyError::BadIssuer { .. }
        ));
    }

    #[test]
    fn rejects_expired_credential() {
        let (issuer, verifier) = issuer_and_verifier();
        let presentation =
            present_email_domain(&issuer.issue(request("sam@tinycloud.xyz")).unwrap())
                .expect("presentation");

        let error = verifier
            .verify(&presentation, &domain_gate(ISSUED_AT + 3600))
            .expect_err("expired credential must fail");

        assert!(matches!(error, OpenCredentialsVerifyError::Expired { .. }));
    }

    #[test]
    fn rejects_missing_email_domain_disclosure() {
        let (issuer, verifier) = issuer_and_verifier();
        let issued = issuer.issue(request("sam@tinycloud.xyz")).unwrap();
        let presentation = present_sd_jwt(&issued, &[]).expect("empty presentation");

        let error = verifier
            .verify(&presentation, &domain_gate(ISSUED_AT + 1))
            .expect_err("missing domain disclosure must fail");

        assert!(matches!(
            error,
            OpenCredentialsVerifyError::MissingDisclosure(EMAIL_DOMAIN_CLAIM)
        ));
    }

    #[test]
    fn rejects_tampered_disclosure() {
        let (issuer, verifier) = issuer_and_verifier();
        let presentation =
            present_email_domain(&issuer.issue(request("sam@tinycloud.xyz")).unwrap())
                .expect("presentation");
        let tampered = tamper_email_domain_disclosure(&presentation, "evil.example");

        let error = verifier
            .verify(&tampered, &domain_gate(ISSUED_AT + 1))
            .expect_err("tampered disclosure must fail");

        assert!(matches!(error, OpenCredentialsVerifyError::SdJwt(_)));
    }

    #[test]
    fn rejects_wrong_domain() {
        let (issuer, verifier) = issuer_and_verifier();
        let presentation =
            present_email_domain(&issuer.issue(request("sam@tinycloud.xyz")).unwrap())
                .expect("presentation");
        let options =
            EmailVerificationOptions::domain_gate([ISSUER], HOLDER, ["example.org"], ISSUED_AT + 1);

        let error = verifier
            .verify(&presentation, &options)
            .expect_err("wrong domain must fail");

        assert!(matches!(
            error,
            OpenCredentialsVerifyError::WrongEmailDomain { .. }
        ));
    }

    #[test]
    fn rejects_holder_mismatch() {
        let (issuer, verifier) = issuer_and_verifier();
        let presentation =
            present_email_domain(&issuer.issue(request("sam@tinycloud.xyz")).unwrap())
                .expect("presentation");
        let options = EmailVerificationOptions::domain_gate(
            [ISSUER],
            "did:key:z6Mkwrongholder",
            ["tinycloud.xyz"],
            ISSUED_AT + 1,
        );

        let error = verifier
            .verify(&presentation, &options)
            .expect_err("holder mismatch must fail");

        assert!(matches!(
            error,
            OpenCredentialsVerifyError::HolderMismatch { .. }
        ));
    }

    #[test]
    fn rejects_unsupported_alg() {
        let (issuer, verifier) = issuer_and_verifier();
        let presentation =
            present_email_domain(&issuer.issue(request("sam@tinycloud.xyz")).unwrap())
                .expect("presentation");
        let unsupported_alg = replace_alg(&presentation, "ES256");

        let error = verifier
            .verify(&unsupported_alg, &domain_gate(ISSUED_AT + 1))
            .expect_err("unsupported alg must fail");

        assert!(matches!(
            error,
            OpenCredentialsVerifyError::UnsupportedAlgorithm(alg) if alg == "ES256"
        ));
    }

    #[test]
    fn rejects_invalid_or_non_ascii_email_domains() {
        assert_eq!(
            email_domain_from_address("sam@TinyCloud.XYZ").unwrap(),
            "tinycloud.xyz"
        );
        assert!(email_domain_from_address("sam@tiny_cloud.xyz").is_err());
        assert!(email_domain_from_address("sam@tínycloud.xyz").is_err());
        assert!(email_domain_from_address("sam@tinycloud..xyz").is_err());
        assert!(email_domain_from_address("sam@@tinycloud.xyz").is_err());
    }

    fn tamper_email_domain_disclosure(presentation: &str, value: &str) -> String {
        let mut parts = presentation
            .split('~')
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let disclosure = parts.get(1).expect("disclosure");
        let bytes = URL_SAFE_NO_PAD
            .decode(disclosure)
            .expect("decoded disclosure");
        let mut disclosure_value: Value = serde_json::from_slice(&bytes).expect("json disclosure");
        let array = disclosure_value.as_array_mut().expect("array disclosure");
        array[2] = json!(value);
        parts[1] =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&disclosure_value).expect("encoded json"));
        parts.join("~")
    }

    fn replace_alg(presentation: &str, alg: &str) -> String {
        let mut sd_parts = presentation
            .split('~')
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let mut jwt_parts = sd_parts[0]
            .split('.')
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        jwt_parts[0] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({ "alg": alg })).unwrap());
        sd_parts[0] = jwt_parts.join(".");
        sd_parts.join("~")
    }
}
