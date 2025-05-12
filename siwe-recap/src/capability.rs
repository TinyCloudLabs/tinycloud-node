use crate::RESOURCE_PREFIX;
use libipld::cid::Cid;
use std::{collections::BTreeMap, fmt::Write};

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DeserializeAs, SerializeAs};

use base64::Engine;
use iri_string::types::UriString;
use siwe::Message;

use ucan_capabilities_object::{
    Ability, AbilityNameRef, AbilityNamespaceRef, Capabilities, CapsInner, ConvertError,
    ConvertResult, NotaBeneCollection,
};

/// Representation of a set of delegated Capabilities.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capability<NB> {
    /// The actions that are allowed for the given target within this namespace.
    #[serde(rename = "att")]
    attenuations: Capabilities<NB>,

    /// Cids of parent delegations which these capabilities are attenuated from
    #[serde(rename = "prf")]
    #[serde_as(as = "Vec<B58Cid>")]
    proof: Vec<Cid>,
}

impl<NB> Capability<NB> {
    /// Create a new empty Capability.
    pub fn new() -> Self {
        Self {
            attenuations: Capabilities::new(),
            proof: Default::default(),
        }
    }

    /// Check if a particular action is allowed for the specified target, or is allowed globally.
    pub fn can<T, A>(
        &self,
        target: T,
        action: A,
    ) -> ConvertResult<Option<&NotaBeneCollection<NB>>, UriString, Ability, T, A>
    where
        T: TryInto<UriString>,
        A: TryInto<Ability>,
    {
        self.attenuations.can(target, action)
    }

    /// Check if a particular action is allowed for the specified target, or is allowed globally, without type conversion.
    pub fn can_do(&self, target: &UriString, action: &Ability) -> Option<&NotaBeneCollection<NB>> {
        self.attenuations.can_do(target, action)
    }

    /// Merge this Capabilities set with another
    pub fn merge<NB1, NB2>(self, other: Capability<NB1>) -> Capability<NB2>
    where
        NB2: From<NB> + From<NB1>,
    {
        let (caps, mut proofs) = self.into_inner();
        for proof in &other.proof {
            if proofs.contains(proof) {
                continue;
            }
            proofs.push(*proof);
        }

        Capability {
            attenuations: caps.merge(other.attenuations),
            proof: proofs,
        }
    }

    /// Add an allowed action for the given target, with a set of note-benes
    pub fn with_action(
        &mut self,
        target: UriString,
        action: Ability,
        nb: impl IntoIterator<Item = BTreeMap<String, NB>>,
    ) -> &mut Self {
        self.attenuations.with_action(target, action, nb);
        self
    }

    /// Add an allowed action for the given target, with a set of note-benes.
    ///
    /// This method automatically converts the provided args into the correct types for convenience.
    pub fn with_action_convert<T, A>(
        &mut self,
        target: T,
        action: A,
        nb: impl IntoIterator<Item = BTreeMap<String, NB>>,
    ) -> Result<&mut Self, ConvertError<T::Error, A::Error>>
    where
        T: TryInto<UriString>,
        A: TryInto<Ability>,
    {
        self.attenuations.with_action_convert(target, action, nb)?;
        Ok(self)
    }

    /// Add a set of allowed action for the given target, with associated note-benes
    pub fn with_actions(
        &mut self,
        target: UriString,
        abilities: impl IntoIterator<Item = (Ability, impl IntoIterator<Item = BTreeMap<String, NB>>)>,
    ) -> &mut Self {
        self.attenuations.with_actions(target, abilities);
        self
    }

    /// Add a set of allowed action for the given target, with associated note-benes.
    ///
    /// This method automatically converts the provided args into the correct types for convenience.
    pub fn with_actions_convert<T, A, N>(
        &mut self,
        target: T,
        abilities: impl IntoIterator<Item = (A, N)>,
    ) -> Result<&mut Self, ConvertError<T::Error, A::Error>>
    where
        T: TryInto<UriString>,
        A: TryInto<Ability>,
        N: IntoIterator<Item = BTreeMap<String, NB>>,
    {
        self.attenuations.with_actions_convert(target, abilities)?;
        Ok(self)
    }

    /// Read the set of abilities granted in this capabilities set
    pub fn abilities(&self) -> &CapsInner<NB> {
        self.attenuations.abilities()
    }

    /// Read the set of abilities granted for a given target in this capabilities set
    pub fn abilities_for<T>(
        &self,
        target: T,
    ) -> Result<Option<&BTreeMap<Ability, NotaBeneCollection<NB>>>, T::Error>
    where
        T: TryInto<UriString>,
    {
        self.attenuations.abilities_for(target)
    }

    /// Read the set of proofs which support the granted capabilities
    pub fn proof(&self) -> &[Cid] {
        &self.proof
    }

    /// Add a supporting proof CID
    pub fn with_proof(mut self, proof: &Cid) -> Self {
        if self.proof.contains(proof) {
            return self;
        }
        self.proof.push(*proof);
        self
    }

    /// Add a set of supporting proofs
    pub fn with_proofs<'l>(mut self, proofs: impl IntoIterator<Item = &'l Cid>) -> Self {
        for proof in proofs {
            if self.proof.contains(proof) {
                continue;
            }
            self.proof.push(*proof);
        }
        self
    }

    fn to_line_groups(
        &self,
    ) -> impl Iterator<Item = (&UriString, AbilityNamespaceRef, Vec<AbilityNameRef>)> {
        self.attenuations
            .abilities()
            .iter()
            .flat_map(|(resource, abilities)| {
                // group abilities by namespace
                abilities
                    .iter()
                    .fold(
                        BTreeMap::<AbilityNamespaceRef, Vec<AbilityNameRef>>::new(),
                        |mut map, (ability, _)| {
                            map.entry(ability.namespace())
                                .or_default()
                                .push(ability.name());
                            map
                        },
                    )
                    .into_iter()
                    .map(move |(namespace, names)| (resource, namespace, names))
            })
    }

    fn to_statement_lines(&self) -> impl Iterator<Item = String> + '_ {
        self.to_line_groups().map(|(resource, namespace, names)| {
            format!(
                "'{}': {} for '{}'.",
                namespace,
                names
                    .iter()
                    .map(|an| format!("'{an}'"))
                    .collect::<Vec<String>>()
                    .join(", "),
                resource
            )
        })
    }

    pub fn into_inner(self) -> (Capabilities<NB>, Vec<Cid>) {
        (self.attenuations, self.proof)
    }
    /// Generate a ReCap statement from capabilities and URI (delegee).
    pub fn to_statement(&self) -> String {
        [
            "I further authorize the stated URI to perform the following actions on my behalf:"
                .to_string(),
            self.to_statement_lines()
                .enumerate()
                .fold(String::new(), |mut acc, (n, line)| {
                    // write! into a string can never fail, unwrapping here is safe
                    write!(acc, " ({}) {line}", n + 1).unwrap();
                    acc
                }),
        ]
        .concat()
    }
}

impl<NB> Capability<NB>
where
    NB: Serialize,
{
    fn encode(&self) -> Result<String, EncodingError> {
        serde_jcs::to_vec(self)
            .map_err(EncodingError::Ser)
            .map(|bytes| {
                let mut encoded = String::new();
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode_string(&bytes, &mut encoded);
                encoded
            })
    }

    /// Apply this capabilities set to a SIWE message by writing to it's statement and resource list
    pub fn build_message(&self, mut message: Message) -> Result<Message, EncodingError> {
        if self.attenuations.abilities().is_empty() {
            return Ok(message);
        }
        let statement = self.to_statement();
        let encoded: UriString = self.try_into()?;
        message.resources.push(encoded);
        let m = message.statement.unwrap_or_default();
        message.statement = Some(if m.is_empty() {
            statement
        } else {
            format!("{m} {statement}")
        });
        Ok(message)
    }
}

impl<NB> Capability<NB>
where
    NB: for<'a> Deserialize<'a>,
{
    /// Extract the encoded capabilities from a SIWE message and ensures the correctness of the statement.
    pub fn extract_and_verify(message: &Message) -> Result<Option<Self>, VerificationError> {
        if let Some(c) = Self::extract(message)? {
            let expected = c.to_statement();
            match &message.statement {
                Some(s) if s.ends_with(&expected) => Ok(Some(c)),
                _ => Err(VerificationError::IncorrectStatement(expected)),
            }
        } else {
            // no caps
            Ok(None)
        }
    }

    fn extract(message: &Message) -> Result<Option<Self>, DecodingError> {
        message
            .resources
            .iter()
            .last()
            .filter(|u| u.as_str().starts_with(RESOURCE_PREFIX))
            .map(Self::try_from)
            .transpose()
    }

    fn decode(encoded: &str) -> Result<Self, DecodingError> {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(DecodingError::Base64Decode)?;
        serde_json::from_slice(&decoded).map_err(DecodingError::De)
    }
}

impl<NB> Default for Capability<NB> {
    fn default() -> Self {
        Self::new()
    }
}

impl<NB> TryFrom<&UriString> for Capability<NB>
where
    NB: for<'a> Deserialize<'a>,
{
    type Error = DecodingError;
    fn try_from(uri: &UriString) -> Result<Self, Self::Error> {
        uri.as_str()
            .strip_prefix(RESOURCE_PREFIX)
            .ok_or_else(|| DecodingError::InvalidResourcePrefix(uri.to_string()))
            .and_then(Capability::decode)
    }
}

impl<NB> TryFrom<&Capability<NB>> for UriString
where
    NB: Serialize,
{
    type Error = EncodingError;
    fn try_from(cap: &Capability<NB>) -> Result<Self, Self::Error> {
        cap.encode()
            .map(|encoded| format!("{RESOURCE_PREFIX}{encoded}"))
            .and_then(|s| s.parse().map_err(EncodingError::UriParse))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum DecodingError {
    #[error("invalid resource prefix (expected prefix: {RESOURCE_PREFIX}, found: {0})")]
    InvalidResourcePrefix(String),
    #[error("failed to decode base64 capability resource: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    #[error("failed to deserialize capability from json: {0}")]
    De(#[from] serde_json::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum EncodingError {
    #[error("unable to parse capability as a URI: {0}")]
    UriParse(#[from] iri_string::validate::Error),
    #[error("failed to serialize capability to json: {0}")]
    Ser(#[from] serde_json::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum VerificationError {
    #[error("error decoding capabilities: {0}")]
    Decoding(#[from] DecodingError),
    #[error("incorrect statement in siwe message, expected to end with: {0}")]
    IncorrectStatement(String),
}

struct B58Cid;

impl SerializeAs<Cid> for B58Cid {
    fn serialize_as<S>(source: &Cid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(
            &source
                .to_string_of_base(libipld::cid::multibase::Base::Base58Btc)
                .map_err(serde::ser::Error::custom)?,
        )
    }
}

impl<'de> DeserializeAs<'de, Cid> for B58Cid {
    fn deserialize_as<D>(deserializer: D) -> Result<Cid, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use std::str::FromStr;
        let s = String::deserialize(deserializer)?;
        if !s.starts_with('z') {
            return Err(serde::de::Error::custom("non-base58btc encoded Cid"));
        };
        Cid::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const JSON_CAP: &str = include_str!("../tests/serialized_cap.json");

    #[test]
    fn deser() {
        let cap: Capability<serde_json::Value> = serde_json::from_str(JSON_CAP).unwrap();
        let reser = serde_jcs::to_string(&cap).unwrap();
        assert_eq!(JSON_CAP.trim(), reser);
    }
}
