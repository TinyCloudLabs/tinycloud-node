use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use opencredentials_verify::{
    normalize_email_domain, EmailCredentialVerifier, EmailVerificationOptions,
    OpenCredentialsVerifyError, VerifiedEmailCredential, EMAIL_CLAIM, EMAIL_DOMAIN_CLAIM,
    EMAIL_VCT, JWK,
};
use policy_core::{EvidenceRequirement, Policy, PolicyCapability};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const VC_CREDENTIAL_PROFILE: &str = "w3c.vc/credential/v1";
pub const OPEN_CREDENTIALS_EMAIL_V1: &str = EMAIL_VCT;
pub const OPEN_CREDENTIALS_LAUNCH_ISSUER: &str = "did:web:issuer.credentials.org";
pub const VC_EVIDENCE_FAMILY: &str = "vc";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationContext {
    pub policy: Policy,
    pub eligible_subject_did: String,
    pub holder_did: String,
    pub requested_capabilities: Vec<PolicyCapability>,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmailDomainRequirements {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub email_domains: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmailDomainPresentation {
    pub sd_jwt: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceProvenance {
    pub family: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_evidence_id: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Satisfaction {
    pub verifier: String,
    pub evidence_ids: Vec<String>,
    pub constraints: Vec<PolicyCapability>,
    pub valid_until: DateTime<Utc>,
    pub status_checked_at: DateTime<Utc>,
    pub provenance: BTreeMap<String, String>,
    pub evidence_provenance: EvidenceProvenance,
}

#[derive(Debug, Error)]
pub enum EvidenceVcError {
    #[error("evidence-verifier-unsupported")]
    UnsupportedVerifier,
    #[error("evidence-requirements-invalid")]
    InvalidRequirements,
    #[error("evidence-presentation-invalid")]
    InvalidPresentation,
    #[error("evidence-authority-missing")]
    MissingAuthority,
    #[error("evidence-issuer-missing")]
    MissingIssuer,
    #[error("evidence-issuer-untrusted")]
    UntrustedIssuer,
    #[error("evidence-domain-invalid")]
    InvalidDomain,
    #[error("evidence-domain-missing")]
    MissingDomain,
    #[error("evidence-freshness-expired")]
    FreshnessExpired,
    #[error("evidence-freshness-unestablishable")]
    FreshnessUnestablishable,
    #[error("evidence-credential-invalid: {0}")]
    OpenCredentials(#[from] OpenCredentialsVerifyError),
}

impl EvidenceVcError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnsupportedVerifier => "evidence-verifier-unsupported",
            Self::InvalidRequirements => "evidence-requirements-invalid",
            Self::InvalidPresentation => "evidence-presentation-invalid",
            Self::MissingAuthority => "evidence-authority-missing",
            Self::MissingIssuer => "evidence-issuer-missing",
            Self::UntrustedIssuer => "evidence-issuer-untrusted",
            Self::InvalidDomain => "evidence-domain-invalid",
            Self::MissingDomain => "evidence-domain-missing",
            Self::FreshnessExpired => "evidence-freshness-expired",
            Self::FreshnessUnestablishable => "evidence-freshness-unestablishable",
            Self::OpenCredentials(_) => "evidence-credential-invalid",
        }
    }
}

pub struct VcEvidenceVerifier {
    issuer_keys: BTreeMap<String, JWK>,
}

impl VcEvidenceVerifier {
    pub fn new(issuer_keys: BTreeMap<String, JWK>) -> Self {
        Self { issuer_keys }
    }

    pub fn verify(
        &self,
        requirement: &EvidenceRequirement,
        presentation: &Value,
        context: &VerificationContext,
    ) -> Result<Satisfaction, EvidenceVcError> {
        if requirement.verifier != VC_CREDENTIAL_PROFILE {
            return Err(EvidenceVcError::UnsupportedVerifier);
        }

        let requirements: EmailDomainRequirements =
            serde_json::from_value(requirement.requirements.clone())
                .map_err(|_| EvidenceVcError::InvalidRequirements)?;
        if requirements.credential_type != OPEN_CREDENTIALS_EMAIL_V1 {
            return Err(EvidenceVcError::InvalidRequirements);
        }
        let allowed_email_domains = requirements
            .email_domains
            .iter()
            .map(|domain| {
                normalize_email_domain(domain).map_err(|_| EvidenceVcError::InvalidDomain)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if allowed_email_domains.is_empty() {
            return Err(EvidenceVcError::MissingDomain);
        }

        let accepted_issuers = requirement
            .authority
            .as_ref()
            .and_then(|authority| authority.accepted_issuers.clone())
            .ok_or(EvidenceVcError::MissingAuthority)?;
        if accepted_issuers.is_empty() {
            return Err(EvidenceVcError::MissingIssuer);
        }

        let presentation: EmailDomainPresentation = serde_json::from_value(presentation.clone())
            .map_err(|_| EvidenceVcError::InvalidPresentation)?;
        let now = context.now.timestamp();

        let mut last_error = None;
        for issuer in &accepted_issuers {
            let Some(jwk) = self.issuer_keys.get(issuer) else {
                last_error = Some(EvidenceVcError::UntrustedIssuer);
                continue;
            };
            let verifier = EmailCredentialVerifier::new_ed25519(jwk)?;
            preflight_credential_claims(&presentation.sd_jwt)?;
            let options = EmailVerificationOptions::domain_gate(
                [issuer.clone()],
                context.eligible_subject_did.clone(),
                allowed_email_domains.clone(),
                now,
            );
            match verifier.verify(&presentation.sd_jwt, &options) {
                Ok(mut verified) => {
                    normalize_disclosed_email_claims(&mut verified)?;
                    enforce_freshness(requirement)?;
                    return Ok(satisfaction(requirement, verified, context.now));
                }
                Err(error) => last_error = Some(EvidenceVcError::OpenCredentials(error)),
            }
        }

        Err(last_error.unwrap_or(EvidenceVcError::MissingIssuer))
    }
}

fn enforce_freshness(requirement: &EvidenceRequirement) -> Result<(), EvidenceVcError> {
    if requirement.freshness.is_some() {
        return Err(EvidenceVcError::FreshnessUnestablishable);
    }
    Ok(())
}

fn preflight_credential_claims(sd_jwt: &str) -> Result<(), EvidenceVcError> {
    let parsed =
        opencredentials_sd_jwt::parse_sd_jwt(sd_jwt).map_err(OpenCredentialsVerifyError::from)?;
    required_unix_timestamp(&parsed.payload, "iat")?;
    required_unix_timestamp(&parsed.payload, "exp")?;
    optional_unix_timestamp(&parsed.payload, "nbf")?;
    Ok(())
}

fn required_unix_timestamp(payload: &Value, claim: &'static str) -> Result<(), EvidenceVcError> {
    match payload.get(claim) {
        Some(Value::Number(number)) if number.as_i64().is_some() => Ok(()),
        Some(_) => Err(OpenCredentialsVerifyError::InvalidClaim(claim).into()),
        None => Err(OpenCredentialsVerifyError::MissingClaim(claim).into()),
    }
}

fn optional_unix_timestamp(payload: &Value, claim: &'static str) -> Result<(), EvidenceVcError> {
    match payload.get(claim) {
        Some(Value::Number(number)) if number.as_i64().is_some() => Ok(()),
        Some(_) => Err(OpenCredentialsVerifyError::InvalidClaim(claim).into()),
        None => Ok(()),
    }
}

fn normalize_disclosed_email_claims(
    credential: &mut VerifiedEmailCredential,
) -> Result<(), EvidenceVcError> {
    let normalized_domain = credential
        .email_domain
        .as_deref()
        .map(normalize_email_domain)
        .transpose()?;

    let normalized_email = credential
        .email
        .as_deref()
        .map(normalize_email_address)
        .transpose()?;

    if let (Some(email), Some(domain)) = (&normalized_email, &normalized_domain) {
        let derived_domain = email
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .ok_or_else(|| {
                OpenCredentialsVerifyError::InvalidEmail(
                    "expected exactly one @ with non-empty local and domain parts".to_string(),
                )
            })?;
        if derived_domain != domain {
            return Err(OpenCredentialsVerifyError::InvalidEmailDomain(format!(
                "email domain `{derived_domain}` does not match disclosed `{domain}`"
            ))
            .into());
        }
    }

    credential.email = normalized_email;
    credential.email_domain = normalized_domain;
    Ok(())
}

fn normalize_email_address(email: &str) -> Result<String, OpenCredentialsVerifyError> {
    if !email.is_ascii() {
        return Err(OpenCredentialsVerifyError::InvalidEmail(
            "email must be ASCII".to_string(),
        ));
    }
    if email.len() > 320 {
        return Err(OpenCredentialsVerifyError::InvalidEmail(
            "email is too long".to_string(),
        ));
    }

    let parts = email.split('@').collect::<Vec<_>>();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(OpenCredentialsVerifyError::InvalidEmail(
            "expected exactly one @ with non-empty local and domain parts".to_string(),
        ));
    }
    if parts[0].len() > 64 {
        return Err(OpenCredentialsVerifyError::InvalidEmail(
            "email local part is too long".to_string(),
        ));
    }

    let local = parts[0].to_ascii_lowercase();
    let domain = normalize_email_domain(parts[1])?;
    Ok(format!("{local}@{domain}"))
}

fn satisfaction(
    requirement: &EvidenceRequirement,
    credential: VerifiedEmailCredential,
    now: DateTime<Utc>,
) -> Satisfaction {
    let mut provenance = BTreeMap::new();
    provenance.insert("issuer".to_string(), credential.issuer.clone());
    provenance.insert("vct".to_string(), credential.vct.clone());
    provenance.insert("holderDid".to_string(), credential.holder_did.clone());
    provenance.insert("issuedAt".to_string(), credential.issued_at.to_string());
    provenance.insert("expiresAt".to_string(), credential.expires_at.to_string());
    if let Some(domain) = &credential.email_domain {
        provenance.insert(EMAIL_DOMAIN_CLAIM.to_string(), domain.clone());
    }
    if let Some(email) = &credential.email {
        provenance.insert(EMAIL_CLAIM.to_string(), email.clone());
        provenance.insert(
            "emailDisclosed".to_string(),
            (!email.is_empty()).to_string(),
        );
    }
    let source_evidence_id = credential
        .payload
        .get("jti")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let evidence_provenance = EvidenceProvenance {
        family: VC_EVIDENCE_FAMILY.to_string(),
        source_evidence_id,
        attributes: provenance.clone(),
    };

    Satisfaction {
        verifier: VC_CREDENTIAL_PROFILE.to_string(),
        evidence_ids: vec![requirement.requirement_id.clone()],
        constraints: Vec::new(),
        valid_until: DateTime::from_timestamp(credential.expires_at, 0).unwrap_or(now),
        status_checked_at: now,
        provenance,
        evidence_provenance,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};
    use opencredentials_sd_jwt::{issue_sd_jwt, Ed25519Signer};
    use opencredentials_verify::{
        present_email, present_email_and_domain, present_email_domain, EmailCredentialIssuer,
        EmailCredentialRequest,
    };
    use policy_core::{EvidenceAuthority, EvidenceFreshness};
    use serde_json::json;

    const ISSUER: &str = "did:web:issuer.tinycloud.xyz";
    const SUBJECT: &str = "did:key:z6Mksubject";
    const HOLDER: &str = "did:key:z6Mkholder";
    const ISSUED_AT: i64 = 1_800_000_000;
    const VECTOR_COMMIT_SHA: &str = "ce40178f08e907f6aa2e82aacfcf4d0839746bd2";
    const LAUNCH_PROFILE_ACCEPT: &str =
        include_str!("../../../test-vectors/launch-credential-profile/accept.json");
    const LAUNCH_PROFILE_REJECT: &str =
        include_str!("../../../test-vectors/launch-credential-profile/reject.json");

    fn issuer_and_registry() -> (EmailCredentialIssuer, VcEvidenceVerifier) {
        let (jwk, verifier) = jwk_and_registry();
        let issuer = EmailCredentialIssuer::new_ed25519(ISSUER, &jwk).expect("issuer");
        (issuer, verifier)
    }

    fn jwk_and_registry() -> (JWK, VcEvidenceVerifier) {
        let jwk = JWK::generate_ed25519().expect("ed25519 jwk");
        let verifier = VcEvidenceVerifier::new(BTreeMap::from([(ISSUER.to_string(), jwk.clone())]));
        (jwk, verifier)
    }

    fn request(email: &str) -> EmailCredentialRequest {
        EmailCredentialRequest::new(SUBJECT, email)
            .with_issued_at(ISSUED_AT)
            .with_ttl_seconds(3600)
            .with_jwt_id("urn:uuid:11111111-1111-1111-1111-111111111111")
    }

    fn requirement() -> EvidenceRequirement {
        EvidenceRequirement {
            requirement_id: "email-domain".to_string(),
            verifier: VC_CREDENTIAL_PROFILE.to_string(),
            requirements: serde_json::json!({
                "type": OPEN_CREDENTIALS_EMAIL_V1,
                "emailDomains": ["TinyCloud.XYZ"]
            }),
            authority: Some(EvidenceAuthority {
                profile: None,
                accepted_issuers: Some(vec![ISSUER.to_string()]),
                allow_owner_authorized_issuer: None,
            }),
            freshness: None,
        }
    }

    fn context(now: i64) -> VerificationContext {
        VerificationContext {
            policy: serde_json::from_value(serde_json::json!({
                "schema": "xyz.tinycloud.policy/policy/v0",
                "policyId": "pol_test",
                "ownerDid": "did:pkh:eip155:1:0xowner",
                "signingKeyDid": "did:key:z6Mksigner",
                "createdAt": "2026-01-01T00:00:00Z",
                "resource": {
                    "resourceType": "listen-transcript",
                    "resourceId": "conv_456",
                    "permissionsCeiling": []
                },
                "when": { "evidence": {
                    "requirementId": "email-domain",
                    "verifier": "w3c.vc/credential/v1",
                    "requirements": { "type": "opencredentials.email/v1", "emailDomains": ["tinycloud.xyz"] }
                }},
                "grant": {
                    "output": "portable-delegation",
                    "maxTtlSeconds": 3600,
                    "delegationMode": "terminal",
                    "revocation": "active_cutoff"
                },
                "signature": {
                    "suite": "eddsa-ed25519-sha256-jcs-v1",
                    "signerDid": "did:key:z6Mksigner",
                    "value": "unused"
                }
            }))
            .unwrap(),
            eligible_subject_did: SUBJECT.to_string(),
            holder_did: HOLDER.to_string(),
            requested_capabilities: Vec::new(),
            now: Utc.timestamp_opt(now, 0).single().unwrap(),
        }
    }

    fn verify_email_domain(
        verifier: &VcEvidenceVerifier,
        requirement: &EvidenceRequirement,
        sd_jwt: String,
        now: i64,
    ) -> Result<Satisfaction, EvidenceVcError> {
        let mut context = context(now);
        context.policy.when = policy_core::Expression::Evidence(policy_core::EvidenceExpression {
            evidence: requirement.clone(),
        });
        verifier.verify(
            requirement,
            &serde_json::json!({ "sdJwt": sd_jwt }),
            &context,
        )
    }

    fn issue_custom_email_credential(jwk: &JWK, email: Value, email_domain: Value) -> String {
        let signer = Ed25519Signer::from_jwk(jwk).expect("signer");
        issue_sd_jwt(
            &json!({
                "iss": ISSUER,
                "sub": SUBJECT,
                "iat": ISSUED_AT,
                "nbf": ISSUED_AT,
                "exp": ISSUED_AT + 3600,
                "vct": OPEN_CREDENTIALS_EMAIL_V1,
                "email": email,
                "emailDomain": email_domain,
                "jti": "urn:uuid:11111111-1111-1111-1111-111111111111"
            }),
            &["/email".to_string(), "/emailDomain".to_string()],
            &signer,
        )
        .expect("custom sd-jwt")
    }

    fn issue_custom_payload(jwk: &JWK, mut payload: Value) -> String {
        let signer = Ed25519Signer::from_jwk(jwk).expect("signer");
        let object = payload.as_object_mut().expect("payload object");
        object.entry("iss").or_insert_with(|| json!(ISSUER));
        object.entry("sub").or_insert_with(|| json!(SUBJECT));
        object
            .entry("vct")
            .or_insert_with(|| json!(OPEN_CREDENTIALS_EMAIL_V1));
        object
            .entry("email")
            .or_insert_with(|| json!("sam@tinycloud.xyz"));
        object
            .entry("emailDomain")
            .or_insert_with(|| json!("tinycloud.xyz"));
        issue_sd_jwt(
            &payload,
            &["/email".to_string(), "/emailDomain".to_string()],
            &signer,
        )
        .expect("custom sd-jwt")
    }

    fn parse_vector_time(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .expect("vector RFC3339 timestamp")
            .with_timezone(&Utc)
    }

    fn vector_jwk(file: &Value) -> JWK {
        let public_key = hex_decode(
            file["profile"]["issuerJwk"]["public_key_hex"]
                .as_str()
                .expect("public key hex"),
        );
        let private_key = hex_decode(
            file["profile"]["issuerJwk"]["private_key_hex"]
                .as_str()
                .expect("private key hex"),
        );
        serde_json::from_value(json!({
            "params": {
                "OKP": {
                    "public_key": public_key,
                    "private_key": private_key
                }
            }
        }))
        .expect("vector jwk")
    }

    fn hex_decode(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("hex byte"))
            .collect()
    }

    fn vector_context(case: &Value, requirement: &EvidenceRequirement) -> VerificationContext {
        let mut context = VerificationContext {
            policy: context(ISSUED_AT).policy,
            eligible_subject_did: case["context"]["eligibleSubjectDid"]
                .as_str()
                .expect("eligible subject")
                .to_string(),
            holder_did: case["context"]["holderDid"]
                .as_str()
                .expect("holder")
                .to_string(),
            requested_capabilities: Vec::new(),
            now: parse_vector_time(case["context"]["now"].as_str().expect("now")),
        };
        context.policy.when = policy_core::Expression::Evidence(policy_core::EvidenceExpression {
            evidence: requirement.clone(),
        });
        context
    }

    #[test]
    fn accepts_selective_email_domain_disclosure() {
        let (issuer, verifier) = issuer_and_registry();
        let issued = issuer.issue(request("Sam@TinyCloud.XYZ")).unwrap();
        let presentation = present_email_domain(&issued).unwrap();

        let satisfaction =
            verify_email_domain(&verifier, &requirement(), presentation, ISSUED_AT + 60).unwrap();

        assert_eq!(satisfaction.verifier, VC_CREDENTIAL_PROFILE);
        assert_eq!(satisfaction.evidence_ids, vec!["email-domain".to_string()]);
        assert_eq!(satisfaction.evidence_provenance.family, VC_EVIDENCE_FAMILY);
        assert_eq!(
            satisfaction
                .evidence_provenance
                .source_evidence_id
                .as_deref(),
            Some("urn:uuid:11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(
            satisfaction
                .provenance
                .get("emailDomain")
                .map(String::as_str),
            Some("tinycloud.xyz")
        );
        assert_eq!(
            satisfaction
                .provenance
                .get("emailDisclosed")
                .map(String::as_str),
            None
        );
    }

    #[test]
    fn rejects_full_email_without_email_domain_disclosure() {
        let (issuer, verifier) = issuer_and_registry();
        let presentation = present_email(&issuer.issue(request("sam@tinycloud.xyz")).unwrap())
            .expect("email-only presentation");

        let error = verify_email_domain(&verifier, &requirement(), presentation, ISSUED_AT + 60)
            .expect_err("domain disclosure is required");

        assert_eq!(error.as_str(), "evidence-credential-invalid");
    }

    #[test]
    fn rejects_wrong_domain() {
        let (issuer, verifier) = issuer_and_registry();
        let presentation =
            present_email_domain(&issuer.issue(request("sam@example.org")).unwrap()).unwrap();

        let error = verify_email_domain(&verifier, &requirement(), presentation, ISSUED_AT + 60)
            .expect_err("wrong domain must fail");

        assert_eq!(error.as_str(), "evidence-credential-invalid");
    }

    #[test]
    fn rejects_wrong_issuer() {
        let jwk = JWK::generate_ed25519().expect("ed25519 jwk");
        let bad_issuer =
            EmailCredentialIssuer::new_ed25519("did:web:issuer.bad", &jwk).expect("issuer");
        let verifier = VcEvidenceVerifier::new(BTreeMap::from([(ISSUER.to_string(), jwk)]));
        let presentation =
            present_email_domain(&bad_issuer.issue(request("sam@tinycloud.xyz")).unwrap()).unwrap();

        let error = verify_email_domain(&verifier, &requirement(), presentation, ISSUED_AT + 60)
            .expect_err("wrong issuer must fail");

        assert_eq!(error.as_str(), "evidence-credential-invalid");
    }

    #[test]
    fn rejects_subject_mismatch() {
        let (issuer, verifier) = issuer_and_registry();
        let issued = issuer
            .issue(
                EmailCredentialRequest::new("did:key:z6Mkwrong", "sam@tinycloud.xyz")
                    .with_issued_at(ISSUED_AT)
                    .with_ttl_seconds(3600),
            )
            .unwrap();
        let presentation = present_email_domain(&issued).unwrap();

        let error = verify_email_domain(&verifier, &requirement(), presentation, ISSUED_AT + 60)
            .expect_err("subject mismatch must fail");

        assert_eq!(error.as_str(), "evidence-credential-invalid");
    }

    #[test]
    fn rejects_expired_credential() {
        let (issuer, verifier) = issuer_and_registry();
        let presentation =
            present_email_domain(&issuer.issue(request("sam@tinycloud.xyz")).unwrap()).unwrap();

        let error = verify_email_domain(&verifier, &requirement(), presentation, ISSUED_AT + 3600)
            .expect_err("expired credential must fail");

        assert_eq!(error.as_str(), "evidence-credential-invalid");
    }

    #[test]
    fn rejects_status_freshness_requirement_even_when_issued_at_is_fresh() {
        let jwk = JWK::generate_ed25519().expect("ed25519 jwk");
        let issuer =
            EmailCredentialIssuer::new_ed25519(OPEN_CREDENTIALS_LAUNCH_ISSUER, &jwk).unwrap();
        let verifier = VcEvidenceVerifier::new(BTreeMap::from([(
            OPEN_CREDENTIALS_LAUNCH_ISSUER.to_string(),
            jwk,
        )]));
        let mut requirement = requirement();
        requirement.authority = Some(EvidenceAuthority {
            profile: None,
            accepted_issuers: Some(vec![OPEN_CREDENTIALS_LAUNCH_ISSUER.to_string()]),
            allow_owner_authorized_issuer: None,
        });
        requirement.freshness = Some(EvidenceFreshness {
            max_status_age_seconds: 300,
        });
        let presentation =
            present_email_domain(&issuer.issue(request("sam@tinycloud.xyz")).unwrap()).unwrap();

        let error = verify_email_domain(&verifier, &requirement, presentation, ISSUED_AT + 60)
            .expect_err("status freshness must fail closed");

        assert_eq!(error.as_str(), "evidence-freshness-unestablishable");
    }

    #[test]
    fn rejects_launch_status_freshness_requirement_without_status_mechanism() {
        let jwk = JWK::generate_ed25519().expect("ed25519 jwk");
        let issuer =
            EmailCredentialIssuer::new_ed25519(OPEN_CREDENTIALS_LAUNCH_ISSUER, &jwk).unwrap();
        let verifier = VcEvidenceVerifier::new(BTreeMap::from([(
            OPEN_CREDENTIALS_LAUNCH_ISSUER.to_string(),
            jwk,
        )]));
        let mut requirement = requirement();
        requirement.authority = Some(EvidenceAuthority {
            profile: None,
            accepted_issuers: Some(vec![OPEN_CREDENTIALS_LAUNCH_ISSUER.to_string()]),
            allow_owner_authorized_issuer: None,
        });
        requirement.freshness = Some(EvidenceFreshness {
            max_status_age_seconds: 300,
        });
        let presentation =
            present_email_domain(&issuer.issue(request("sam@tinycloud.xyz")).unwrap()).unwrap();

        let error = verify_email_domain(&verifier, &requirement, presentation, ISSUED_AT + 60)
            .expect_err("requirement-level status freshness must fail closed");

        assert_eq!(error.as_str(), "evidence-freshness-unestablishable");
    }

    #[test]
    fn rejects_status_freshness_for_any_accepted_issuer_without_status_mechanism() {
        let (issuer, verifier) = issuer_and_registry();
        let mut requirement = requirement();
        requirement.freshness = Some(EvidenceFreshness {
            max_status_age_seconds: 300,
        });
        let presentation =
            present_email_domain(&issuer.issue(request("sam@tinycloud.xyz")).unwrap()).unwrap();

        let error = verify_email_domain(&verifier, &requirement, presentation, ISSUED_AT + 60)
            .expect_err("status freshness cannot be established for any issuer");

        assert_eq!(error.as_str(), "evidence-freshness-unestablishable");
    }

    #[test]
    fn rejects_requirement_freshness_when_context_policy_copy_lacks_freshness() {
        let (issuer, verifier) = issuer_and_registry();
        let mut requirement = requirement();
        requirement.freshness = Some(EvidenceFreshness {
            max_status_age_seconds: 300,
        });
        let presentation =
            present_email_domain(&issuer.issue(request("sam@tinycloud.xyz")).unwrap()).unwrap();
        let context = context(ISSUED_AT + 60);

        let error = verifier
            .verify(
                &requirement,
                &serde_json::json!({ "sdJwt": presentation }),
                &context,
            )
            .expect_err("freshness requirement must not depend on policy copy");

        assert_eq!(error.as_str(), "evidence-freshness-unestablishable");
    }

    #[test]
    fn freshness_absent_keeps_expiry_only_acceptance() {
        let (issuer, verifier) = issuer_and_registry();
        let mut requirement = requirement();
        requirement.freshness = None;
        let presentation =
            present_email_domain(&issuer.issue(request("sam@tinycloud.xyz")).unwrap()).unwrap();

        verify_email_domain(&verifier, &requirement, presentation, ISSUED_AT + 60)
            .expect("fresh unexpired credential remains accepted without freshness requirement");
    }

    #[test]
    fn normalizes_disclosed_email_and_domain_in_returned_claims() {
        let (issuer, verifier) = issuer_and_registry();
        let mut requirement = requirement();
        requirement.freshness = None;
        let issued = issuer
            .issue(request("Sam+Tag.Dot@TinyCloud.XYZ"))
            .expect("issued credential");
        let presentation = present_email_and_domain(&issued).expect("email and domain disclosure");

        let satisfaction =
            verify_email_domain(&verifier, &requirement, presentation, ISSUED_AT + 60).unwrap();

        assert_eq!(
            satisfaction.provenance.get(EMAIL_CLAIM).map(String::as_str),
            Some("sam+tag.dot@tinycloud.xyz")
        );
        assert_eq!(
            satisfaction
                .provenance
                .get(EMAIL_DOMAIN_CLAIM)
                .map(String::as_str),
            Some("tinycloud.xyz")
        );
    }

    #[test]
    fn rejects_non_ascii_disclosed_email_local_part() {
        let (jwk, verifier) = jwk_and_registry();
        let mut requirement = requirement();
        requirement.freshness = None;
        let issued =
            issue_custom_email_credential(&jwk, json!("sám@tinycloud.xyz"), json!("tinycloud.xyz"));
        let presentation = present_email_and_domain(&issued).expect("email and domain disclosure");

        let error = verify_email_domain(&verifier, &requirement, presentation, ISSUED_AT + 60)
            .expect_err("non-ASCII local part must fail closed");

        assert_eq!(error.as_str(), "evidence-credential-invalid");
    }

    #[test]
    fn rejects_non_ascii_disclosed_email_domain() {
        let (jwk, verifier) = jwk_and_registry();
        let mut requirement = requirement();
        requirement.freshness = None;
        let issued =
            issue_custom_email_credential(&jwk, json!("sam@tinycloud.xyz"), json!("tínycloud.xyz"));
        let presentation = present_email_and_domain(&issued).expect("email and domain disclosure");

        let error = verify_email_domain(&verifier, &requirement, presentation, ISSUED_AT + 60)
            .expect_err("non-ASCII domain must fail closed");

        assert_eq!(error.as_str(), "evidence-credential-invalid");
    }

    #[test]
    fn rejects_disclosed_email_domain_cross_check_mismatch_after_normalization() {
        let (jwk, verifier) = jwk_and_registry();
        let mut requirement = requirement();
        requirement.freshness = None;
        let issued =
            issue_custom_email_credential(&jwk, json!("sam@evil.example"), json!("TinyCloud.XYZ"));
        let presentation = present_email_and_domain(&issued).expect("email and domain disclosure");

        let error = verify_email_domain(&verifier, &requirement, presentation, ISSUED_AT + 60)
            .expect_err("email/domain mismatch must fail closed");

        assert_eq!(error.as_str(), "evidence-credential-invalid");
    }

    #[test]
    fn rejects_email_without_exactly_one_at() {
        let (jwk, verifier) = jwk_and_registry();
        let mut requirement = requirement();
        requirement.freshness = None;
        let issued = issue_custom_email_credential(
            &jwk,
            json!("sam@@tinycloud.xyz"),
            json!("tinycloud.xyz"),
        );
        let presentation = present_email_and_domain(&issued).expect("email and domain disclosure");

        let error = verify_email_domain(&verifier, &requirement, presentation, ISSUED_AT + 60)
            .expect_err("malformed email must fail closed");

        assert_eq!(error.as_str(), "evidence-credential-invalid");
    }

    #[test]
    fn rejects_oversized_disclosed_email_claim() {
        let (jwk, verifier) = jwk_and_registry();
        let mut requirement = requirement();
        requirement.freshness = None;
        let oversized_local = format!("{}@tinycloud.xyz", "a".repeat(65));
        let issued =
            issue_custom_email_credential(&jwk, json!(oversized_local), json!("tinycloud.xyz"));
        let presentation = present_email_and_domain(&issued).expect("email and domain disclosure");

        let error = verify_email_domain(&verifier, &requirement, presentation, ISSUED_AT + 60)
            .expect_err("oversized local part must fail closed");

        assert_eq!(error.as_str(), "evidence-credential-invalid");
    }

    #[test]
    fn rejects_unknown_requirement_fields() {
        let (_issuer, verifier) = issuer_and_registry();
        let mut requirement = requirement();
        requirement.requirements = json!({
            "type": OPEN_CREDENTIALS_EMAIL_V1,
            "emailDomains": ["tinycloud.xyz"],
            "unexpected": true
        });

        let error = verifier
            .verify(
                &requirement,
                &json!({ "sdJwt": "unused" }),
                &context(ISSUED_AT + 60),
            )
            .expect_err("unknown requirement field must fail");

        assert_eq!(error.as_str(), "evidence-requirements-invalid");
    }

    #[test]
    fn rejects_unknown_presentation_fields() {
        let (issuer, verifier) = issuer_and_registry();
        let presentation =
            present_email_domain(&issuer.issue(request("sam@tinycloud.xyz")).unwrap()).unwrap();

        let error = verifier
            .verify(
                &requirement(),
                &json!({ "sdJwt": presentation, "status": { "state": "active" } }),
                &context(ISSUED_AT + 60),
            )
            .expect_err("unknown presentation field must fail");

        assert_eq!(error.as_str(), "evidence-presentation-invalid");
    }

    #[test]
    fn rejects_type_mismatched_presentation() {
        let (_issuer, verifier) = issuer_and_registry();

        let error = verifier
            .verify(
                &requirement(),
                &json!({ "sdJwt": 42 }),
                &context(ISSUED_AT + 60),
            )
            .expect_err("type-mismatched presentation must fail");

        assert_eq!(error.as_str(), "evidence-presentation-invalid");
    }

    #[test]
    fn rejects_malformed_sd_jwt_without_panicking() {
        let (_issuer, verifier) = issuer_and_registry();

        let error = verifier
            .verify(
                &requirement(),
                &json!({ "sdJwt": "not-a-compact-jwt" }),
                &context(ISSUED_AT + 60),
            )
            .expect_err("malformed SD-JWT must fail");

        assert_eq!(error.as_str(), "evidence-credential-invalid");
    }

    #[test]
    fn rejects_truncated_signature_without_panicking() {
        let (issuer, verifier) = issuer_and_registry();
        let mut presentation =
            present_email_domain(&issuer.issue(request("sam@tinycloud.xyz")).unwrap()).unwrap();
        let signature_index = presentation
            .find('~')
            .and_then(|tilde| presentation[..tilde].rfind('.'))
            .expect("signature segment");
        presentation.truncate(signature_index + 2);
        presentation.push('~');

        let error = verify_email_domain(&verifier, &requirement(), presentation, ISSUED_AT + 60)
            .expect_err("truncated signature must fail");

        assert_eq!(error.as_str(), "evidence-credential-invalid");
    }

    #[test]
    fn rejects_malformed_date_claim_before_signature_validity() {
        let (jwk, verifier) = jwk_and_registry();
        let issued = issue_custom_payload(
            &jwk,
            json!({
                "iat": "2027-01-15T08:00:00Z",
                "nbf": ISSUED_AT,
                "exp": ISSUED_AT + 3600,
            }),
        );
        let mut presentation = present_email_domain(&issued).expect("domain disclosure");
        let tilde = presentation.find('~').expect("issuer jwt end");
        let issuer_jwt = &presentation[..tilde];
        let mut jwt_parts = issuer_jwt.split('.').collect::<Vec<_>>();
        jwt_parts[2] = "AA";
        presentation = format!("{}{}", jwt_parts.join("."), &presentation[tilde..]);

        let error = verify_email_domain(&verifier, &requirement(), presentation, ISSUED_AT + 60)
            .expect_err("malformed date claim must fail before signature verification");

        assert_eq!(error.as_str(), "evidence-credential-invalid");
    }

    #[test]
    fn rejects_missing_issuer_authority_configuration() {
        let (issuer, verifier) = issuer_and_registry();
        let mut requirement = requirement();
        requirement.authority = None;
        let presentation =
            present_email_domain(&issuer.issue(request("sam@tinycloud.xyz")).unwrap()).unwrap();

        let error = verify_email_domain(&verifier, &requirement, presentation, ISSUED_AT + 60)
            .expect_err("missing authority must fail");

        assert_eq!(error.as_str(), "evidence-authority-missing");
    }

    #[test]
    fn rejects_untrusted_issuer_configuration() {
        let (issuer, _verifier) = issuer_and_registry();
        let verifier = VcEvidenceVerifier::new(BTreeMap::new());
        let presentation =
            present_email_domain(&issuer.issue(request("sam@tinycloud.xyz")).unwrap()).unwrap();

        let error = verify_email_domain(&verifier, &requirement(), presentation, ISSUED_AT + 60)
            .expect_err("missing issuer key must fail");

        assert_eq!(error.as_str(), "evidence-issuer-untrusted");
    }

    #[test]
    fn frozen_launch_accept_vector_passes_verifier_entry_point() {
        assert_eq!(VECTOR_COMMIT_SHA.len(), 40);
        let file: Value = serde_json::from_str(LAUNCH_PROFILE_ACCEPT).expect("accept vector");
        let case = &file["cases"][0];
        let issuer = file["profile"]["sdkDefaultAcceptedIssuers"][0]
            .as_str()
            .expect("issuer")
            .to_string();
        let verifier = VcEvidenceVerifier::new(BTreeMap::from([(issuer, vector_jwk(&file))]));
        let requirement: EvidenceRequirement =
            serde_json::from_value(case["requirement"].clone()).expect("requirement");

        verifier
            .verify(
                &requirement,
                &case["evidencePresentation"],
                &vector_context(case, &requirement),
            )
            .expect("accept vector must pass");
    }

    #[test]
    fn frozen_launch_reject_vectors_fail_with_expected_codes() {
        let file: Value = serde_json::from_str(LAUNCH_PROFILE_REJECT).expect("reject vector");
        let issuer = file["profile"]["sdkDefaultAcceptedIssuers"][0]
            .as_str()
            .expect("issuer")
            .to_string();

        for case in file["cases"].as_array().expect("cases") {
            let Some(expected_code) = case["rejection_code"].as_str() else {
                continue;
            };
            if expected_code == "enrollment-binding-mismatch" {
                let requirement: EvidenceRequirement =
                    serde_json::from_value(case["requirement"].clone()).expect("requirement");
                let presentation: policy_core::GrantPresentation =
                    serde_json::from_value(case["grantPresentation"].clone())
                        .expect("grant presentation");
                let context = vector_context(case, &requirement);
                let verifier =
                    VcEvidenceVerifier::new(BTreeMap::from([(issuer.clone(), vector_jwk(&file))]));
                verifier
                    .verify(&requirement, &case["evidencePresentation"], &context)
                    .expect("holder enrollment binding is enforced outside policy-evidence-vc");
                let error = policy_core::validate_enrolled_agent_binding(
                    &presentation,
                    &context.policy,
                    &policy_core::EnrollmentStatusTracker::new(),
                    context.now,
                )
                .expect_err("holder enrollment binding vector must reject");
                assert_eq!(error.as_str(), expected_code, "{}", case["name"]);
                continue;
            }
            let requirement: EvidenceRequirement =
                serde_json::from_value(case["requirement"].clone()).expect("requirement");
            let verifier =
                VcEvidenceVerifier::new(BTreeMap::from([(issuer.clone(), vector_jwk(&file))]));

            let error = match verifier.verify(
                &requirement,
                &case["evidencePresentation"],
                &vector_context(case, &requirement),
            ) {
                Ok(_) => panic!("{} must reject", case["name"]),
                Err(error) => error,
            };

            assert_eq!(error.as_str(), expected_code, "{}", case["name"]);
        }
    }

    #[test]
    fn rejects_non_ascii_required_domain() {
        let (_issuer, verifier) = issuer_and_registry();
        let mut requirement = requirement();
        requirement.requirements = serde_json::json!({
            "type": OPEN_CREDENTIALS_EMAIL_V1,
            "emailDomains": ["tínycloud.xyz"]
        });

        let error = verifier
            .verify(
                &requirement,
                &serde_json::json!({ "sdJwt": "unused" }),
                &context(ISSUED_AT + 60),
            )
            .expect_err("invalid domain must fail before credential parse");

        assert_eq!(error.as_str(), "evidence-domain-invalid");
    }
}
