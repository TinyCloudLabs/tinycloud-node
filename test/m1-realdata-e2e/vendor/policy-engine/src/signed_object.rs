use crate::capability::hex_lower;
use crate::crypto;
use crate::jcs;
use crate::types::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const POLICY_DOMAIN: &[u8] = b"xyz.tinycloud.policy/policy/v0\0";
pub const POLICY_STATUS_DOMAIN: &[u8] = b"xyz.tinycloud.policy/status/v0\0";
pub const POLICY_ENGINE_RECORD_DOMAIN: &[u8] = b"xyz.tinycloud.policy/engine-record/v0\0";
pub const OPERATIONAL_KEY_AUTHORIZATION_DOMAIN: &[u8] =
    b"xyz.tinycloud.auth/key-authorization/v0\0";
pub const OPERATIONAL_KEY_STATUS_DOMAIN: &[u8] = b"xyz.tinycloud.auth/key-status/v0\0";
pub const HOLDER_ENROLLMENT_DOMAIN: &[u8] = b"xyz.tinycloud.policy/holder-enrollment/v0\0";
pub const HOLDER_ENROLLMENT_STATUS_DOMAIN: &[u8] =
    b"xyz.tinycloud.policy/holder-enrollment-status/v0\0";
pub const GRANT_CHALLENGE_DOMAIN: &[u8] = b"xyz.tinycloud.policy/challenge/v0\0";
pub const GRANT_PRESENTATION_DOMAIN: &[u8] = b"xyz.tinycloud.policy/GrantPresentation/v0\0";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignedObjectError {
    #[error("schema-invalid")]
    SchemaInvalid,
    #[error("canonicalization-mismatch")]
    CanonicalizationMismatch,
    #[error("digest-mismatch")]
    DigestMismatch,
    #[error("id-mismatch")]
    IdMismatch,
    #[error("signer-not-authorized")]
    SignerNotAuthorized,
    #[error("signature-invalid")]
    SignatureInvalid,
}

impl SignedObjectError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SchemaInvalid => "schema-invalid",
            Self::CanonicalizationMismatch => "canonicalization-mismatch",
            Self::DigestMismatch => "digest-mismatch",
            Self::IdMismatch => "id-mismatch",
            Self::SignerNotAuthorized => "signer-not-authorized",
            Self::SignatureInvalid => "signature-invalid",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedObjectType {
    Policy,
    PolicyStatus,
    PolicyEngineRecord,
    OperationalKeyAuthorization,
    OperationalKeyStatus,
    HolderEnrollment,
    HolderEnrollmentStatus,
    GrantChallenge,
}

impl SignedObjectType {
    pub fn from_schema(schema: &str) -> Option<Self> {
        match schema {
            POLICY_SCHEMA => Some(Self::Policy),
            POLICY_STATUS_SCHEMA => Some(Self::PolicyStatus),
            POLICY_ENGINE_RECORD_SCHEMA => Some(Self::PolicyEngineRecord),
            OPERATIONAL_KEY_AUTHORIZATION_SCHEMA => Some(Self::OperationalKeyAuthorization),
            OPERATIONAL_KEY_STATUS_SCHEMA => Some(Self::OperationalKeyStatus),
            HOLDER_ENROLLMENT_SCHEMA => Some(Self::HolderEnrollment),
            HOLDER_ENROLLMENT_STATUS_SCHEMA => Some(Self::HolderEnrollmentStatus),
            GRANT_CHALLENGE_SCHEMA => Some(Self::GrantChallenge),
            _ => None,
        }
    }

    pub fn prefix(self) -> &'static str {
        match self {
            Self::Policy => "pol_",
            Self::PolicyStatus => "polst_",
            Self::PolicyEngineRecord => "peng_",
            Self::OperationalKeyAuthorization => "opka_",
            Self::OperationalKeyStatus => "opks_",
            Self::HolderEnrollment => "henr_",
            Self::HolderEnrollmentStatus => "henrst_",
            Self::GrantChallenge => "gchal_",
        }
    }

    pub fn id_field(self) -> &'static str {
        match self {
            Self::Policy => "policyId",
            Self::PolicyStatus => "statusId",
            Self::PolicyEngineRecord => "engineRecordId",
            Self::OperationalKeyAuthorization => "authorizationId",
            Self::OperationalKeyStatus => "statusId",
            Self::HolderEnrollment => "enrollmentId",
            Self::HolderEnrollmentStatus => "statusId",
            Self::GrantChallenge => "challengeId",
        }
    }

    pub fn domain(self) -> &'static [u8] {
        match self {
            Self::Policy => POLICY_DOMAIN,
            Self::PolicyStatus => POLICY_STATUS_DOMAIN,
            Self::PolicyEngineRecord => POLICY_ENGINE_RECORD_DOMAIN,
            Self::OperationalKeyAuthorization => OPERATIONAL_KEY_AUTHORIZATION_DOMAIN,
            Self::OperationalKeyStatus => OPERATIONAL_KEY_STATUS_DOMAIN,
            Self::HolderEnrollment => HOLDER_ENROLLMENT_DOMAIN,
            Self::HolderEnrollmentStatus => HOLDER_ENROLLMENT_STATUS_DOMAIN,
            Self::GrantChallenge => GRANT_CHALLENGE_DOMAIN,
        }
    }
}

pub trait SignedObject:
    SchemaBound + Serialize + DeserializeOwned + Clone + std::fmt::Debug + Sized
{
    const TYPE: SignedObjectType;

    fn id(&self) -> &str;
    fn signature(&self) -> &Signature;
    fn signer_authorized_by_shape(&self) -> bool;
}

macro_rules! impl_signed_object {
    ($ty:ty, $object_type:expr, $id:ident, direct_signer = $signer:ident) => {
        impl SignedObject for $ty {
            const TYPE: SignedObjectType = $object_type;

            fn id(&self) -> &str {
                &self.$id
            }

            fn signature(&self) -> &Signature {
                &self.signature
            }

            fn signer_authorized_by_shape(&self) -> bool {
                self.signature.signer_did == self.$signer
            }
        }
    };
    ($ty:ty, $object_type:expr, $id:ident, owner_signer = $owner:ident) => {
        impl SignedObject for $ty {
            const TYPE: SignedObjectType = $object_type;

            fn id(&self) -> &str {
                &self.$id
            }

            fn signature(&self) -> &Signature {
                &self.signature
            }

            fn signer_authorized_by_shape(&self) -> bool {
                self.signature.signer_did == self.$owner
            }
        }
    };
    ($ty:ty, $object_type:expr, $id:ident, unchecked_signer) => {
        impl SignedObject for $ty {
            const TYPE: SignedObjectType = $object_type;

            fn id(&self) -> &str {
                &self.$id
            }

            fn signature(&self) -> &Signature {
                &self.signature
            }

            fn signer_authorized_by_shape(&self) -> bool {
                true
            }
        }
    };
}

impl_signed_object!(
    Policy,
    SignedObjectType::Policy,
    policy_id,
    direct_signer = signing_key_did
);
impl_signed_object!(
    PolicyStatus,
    SignedObjectType::PolicyStatus,
    status_id,
    direct_signer = signing_key_did
);
impl_signed_object!(
    PolicyEngineRecord,
    SignedObjectType::PolicyEngineRecord,
    engine_record_id,
    unchecked_signer
);
impl_signed_object!(
    OperationalKeyAuthorization,
    SignedObjectType::OperationalKeyAuthorization,
    authorization_id,
    owner_signer = owner_did
);
impl_signed_object!(
    OperationalKeyStatus,
    SignedObjectType::OperationalKeyStatus,
    status_id,
    unchecked_signer
);
impl_signed_object!(
    HolderEnrollment,
    SignedObjectType::HolderEnrollment,
    enrollment_id,
    direct_signer = signing_key_did
);
impl_signed_object!(
    HolderEnrollmentStatus,
    SignedObjectType::HolderEnrollmentStatus,
    status_id,
    direct_signer = signing_key_did
);
impl_signed_object!(
    GrantChallenge,
    SignedObjectType::GrantChallenge,
    challenge_id,
    unchecked_signer
);

#[derive(Clone, Debug, PartialEq)]
pub enum VerifiedSignedObject {
    Policy(Policy),
    PolicyStatus(PolicyStatus),
    PolicyEngineRecord(PolicyEngineRecord),
    OperationalKeyAuthorization(OperationalKeyAuthorization),
    OperationalKeyStatus(OperationalKeyStatus),
    HolderEnrollment(HolderEnrollment),
    HolderEnrollmentStatus(HolderEnrollmentStatus),
    GrantChallenge(GrantChallenge),
}

pub fn verify_signed_object_value(
    value: &Value,
) -> Result<VerifiedSignedObject, SignedObjectError> {
    let schema = value
        .get("schema")
        .and_then(Value::as_str)
        .ok_or(SignedObjectError::SchemaInvalid)?;
    match SignedObjectType::from_schema(schema).ok_or(SignedObjectError::SchemaInvalid)? {
        SignedObjectType::Policy => {
            verify_signed_object::<Policy>(value).map(VerifiedSignedObject::Policy)
        }
        SignedObjectType::PolicyStatus => {
            verify_signed_object::<PolicyStatus>(value).map(VerifiedSignedObject::PolicyStatus)
        }
        SignedObjectType::PolicyEngineRecord => verify_signed_object::<PolicyEngineRecord>(value)
            .map(VerifiedSignedObject::PolicyEngineRecord),
        SignedObjectType::OperationalKeyAuthorization => {
            verify_signed_object::<OperationalKeyAuthorization>(value)
                .map(VerifiedSignedObject::OperationalKeyAuthorization)
        }
        SignedObjectType::OperationalKeyStatus => {
            verify_signed_object::<OperationalKeyStatus>(value)
                .map(VerifiedSignedObject::OperationalKeyStatus)
        }
        SignedObjectType::HolderEnrollment => verify_signed_object::<HolderEnrollment>(value)
            .map(VerifiedSignedObject::HolderEnrollment),
        SignedObjectType::HolderEnrollmentStatus => {
            verify_signed_object::<HolderEnrollmentStatus>(value)
                .map(VerifiedSignedObject::HolderEnrollmentStatus)
        }
        SignedObjectType::GrantChallenge => {
            verify_signed_object::<GrantChallenge>(value).map(VerifiedSignedObject::GrantChallenge)
        }
    }
}

pub fn verify_signed_object<T: SignedObject>(value: &Value) -> Result<T, SignedObjectError> {
    let typed: T =
        serde_json::from_value(value.clone()).map_err(|_| SignedObjectError::SchemaInvalid)?;
    if typed.schema_value() != T::expected_schema() {
        return Err(SignedObjectError::SchemaInvalid);
    }

    let digest = digest_signed_object(&typed)?;
    let expected_id = compute_signed_object_id(T::TYPE, &digest);
    if typed.id() != expected_id {
        if typed.id().starts_with(T::TYPE.prefix()) {
            return Err(SignedObjectError::DigestMismatch);
        }
        return Err(SignedObjectError::IdMismatch);
    }

    if !typed.signer_authorized_by_shape() {
        return Err(SignedObjectError::SignerNotAuthorized);
    }

    crypto::verify_signature(typed.signature(), &digest)
        .map_err(|_| SignedObjectError::SignatureInvalid)?;
    Ok(typed)
}

pub fn digest_signed_object<T: SignedObject>(object: &T) -> Result<[u8; 32], SignedObjectError> {
    let unsigned = unsigned_signed_object_value(object)?;
    Ok(digest_value(T::TYPE.domain(), &unsigned))
}

pub fn unsigned_signed_object_value<T: SignedObject>(
    object: &T,
) -> Result<Value, SignedObjectError> {
    let mut value = serde_json::to_value(object).map_err(|_| SignedObjectError::SchemaInvalid)?;
    let object = value
        .as_object_mut()
        .ok_or(SignedObjectError::SchemaInvalid)?;
    object.remove(T::TYPE.id_field());
    object.remove("signature");
    Ok(Value::Object(object.clone()))
}

pub fn compute_signed_object_id(object_type: SignedObjectType, digest: &[u8; 32]) -> String {
    let mut id = String::from(object_type.prefix());
    id.push_str(&base32lower_no_pad(digest));
    id
}

pub fn validate_jcs_bytes(value: &Value, bytes: &[u8]) -> Result<(), SignedObjectError> {
    if jcs::canonicalize(value) == bytes {
        Ok(())
    } else {
        Err(SignedObjectError::CanonicalizationMismatch)
    }
}

pub fn digest_grant_presentation(
    presentation: &GrantPresentation,
) -> Result<[u8; 32], SignedObjectError> {
    if presentation.schema != GRANT_PRESENTATION_SCHEMA {
        return Err(SignedObjectError::SchemaInvalid);
    }
    let mut value =
        serde_json::to_value(presentation).map_err(|_| SignedObjectError::SchemaInvalid)?;
    let object = value
        .as_object_mut()
        .ok_or(SignedObjectError::SchemaInvalid)?;
    object.remove("holderSignature");
    Ok(digest_value(
        GRANT_PRESENTATION_DOMAIN,
        &Value::Object(object.clone()),
    ))
}

pub fn verify_grant_presentation_holder_signature(
    presentation: &GrantPresentation,
) -> Result<(), SignedObjectError> {
    let digest = digest_grant_presentation(presentation)?;
    crypto::verify_signature(&presentation.holder_signature, &digest)
        .map_err(|_| SignedObjectError::SignatureInvalid)
}

pub fn digest_value(domain: &[u8], value: &Value) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(jcs::canonicalize(value));
    hasher.finalize().into()
}

pub fn digest_hex(digest: &[u8; 32]) -> String {
    hex_lower(digest)
}

fn base32lower_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            let index = ((buffer >> (bits - 5)) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32lower_matches_profile_length() {
        let digest = [0_u8; 32];
        let encoded = base32lower_no_pad(&digest);
        assert_eq!(encoded.len(), 52);
        assert!(encoded.chars().all(|ch| ch == 'a'));
    }
}
