mod capability;

pub use capability::{Capability, DecodingError, EncodingError, VerificationError};
pub use ucan_capabilities_object::{
    AbilityName, AbilityNameRef, AbilityNamespace, AbilityNamespaceRef, AbilityRef, CapsInner,
    ConvertError, NotaBeneCollection,
};

/// The prefix for a ReCap uri.
pub const RESOURCE_PREFIX: &str = "urn:recap:";

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::Value;
    use siwe::Message;

    const SIWE_WITH_INTERLEAVED_RES: &str =
        include_str!("../tests/siwe_with_interleaved_resources.txt");
    const SIWE_WITH_STATEMENT_NO_CAPS: &str =
        include_str!("../tests/siwe_with_statement_no_caps.txt");
    const SIWE_WITH_STATEMENT: &str = include_str!("../tests/siwe_with_statement.txt");
    const SIWE_NO_CAPS: &str = include_str!("../tests/siwe_with_no_caps.txt");
    const SIWE: &str = include_str!("../tests/siwe_with_caps.txt");

    #[test]
    fn no_caps_statement_append() {
        let msg = Capability::<Value>::default()
            .build_message(Message {
                domain: "example.com".parse().unwrap(),
                address: Default::default(),
                statement: Some("Some custom statement.".into()),
                uri: "did:key:example".parse().unwrap(),
                version: siwe::Version::V1,
                chain_id: 1,
                nonce: "mynonce1".into(),
                issued_at: "2022-06-21T12:00:00.000Z".parse().unwrap(),
                expiration_time: None,
                not_before: None,
                request_id: None,
                resources: vec![],
            })
            .expect("failed to build SIWE delegation");

        assert_eq!(
            SIWE_WITH_STATEMENT_NO_CAPS,
            msg.to_string(),
            "generated SIWE message did not match expectation"
        );
    }

    #[test]
    fn build_delegation_statement_append() {
        let mut cap = Capability::<Value>::default();
        cap.with_action_convert("credential:*", "credential/present", [])
            .unwrap();

        let msg = cap
            .build_message(Message {
                domain: "example.com".parse().unwrap(),
                address: Default::default(),
                statement: Some("Some custom statement.".into()),
                uri: "did:key:example".parse().unwrap(),
                version: siwe::Version::V1,
                chain_id: 1,
                nonce: "mynonce1".into(),
                issued_at: "2022-06-21T12:00:00.000Z".parse().unwrap(),
                expiration_time: None,
                not_before: None,
                request_id: None,
                resources: vec!["http://example.com".parse().unwrap()],
            })
            .expect("failed to build SIWE delegation");

        assert_eq!(
            SIWE_WITH_STATEMENT.trim(),
            msg.to_string(),
            "generated SIWE message did not match expectation"
        );
    }

    #[test]
    fn no_caps() {
        let msg = Capability::<Value>::default()
            .build_message(Message {
                domain: "example.com".parse().unwrap(),
                address: Default::default(),
                statement: None,
                uri: "did:key:example".parse().unwrap(),
                version: siwe::Version::V1,
                chain_id: 1,
                nonce: "mynonce1".into(),
                issued_at: "2022-06-21T12:00:00.000Z".parse().unwrap(),
                expiration_time: None,
                not_before: None,
                request_id: None,
                resources: vec![],
            })
            .expect("failed to build SIWE delegation");

        assert_eq!(
            SIWE_NO_CAPS,
            msg.to_string(),
            "generated SIWE message did not match expectation"
        );
    }

    #[test]
    fn build_delegation() {
        let msg = Capability::<Value>::default()
            .with_actions_convert("urn:credential:type:type1", [("credential/present", [])])
            .unwrap()
            .with_actions_convert(
                "kepler:ens:example.eth://default/kv",
                [("kv/list", []), ("kv/get", []), ("kv/metadata", [])],
            )
            .unwrap()
            .with_actions_convert(
                "kepler:ens:example.eth://default/kv/public",
                [
                    ("kv/list", []),
                    ("kv/get", []),
                    ("kv/metadata", []),
                    ("kv/put", []),
                    ("kv/delete", []),
                ],
            )
            .unwrap()
            .with_actions_convert(
                "kepler:ens:example.eth://default/kv/dapp-space",
                [
                    ("kv/list", []),
                    ("kv/get", []),
                    ("kv/metadata", []),
                    ("kv/put", []),
                    ("kv/delete", []),
                ],
            )
            .unwrap()
            .build_message(Message {
                domain: "example.com".parse().unwrap(),
                address: Default::default(),
                statement: None,
                uri: "did:key:example".parse().unwrap(),
                version: siwe::Version::V1,
                chain_id: 1,
                nonce: "mynonce1".into(),
                issued_at: "2022-06-21T12:00:00.000Z".parse().unwrap(),
                expiration_time: None,
                not_before: None,
                request_id: None,
                resources: vec![],
            })
            .expect("failed to build SIWE delegation");

        assert_eq!(
            SIWE.trim(),
            msg.to_string(),
            "generated SIWE message did not match expectation"
        );
    }

    #[test]
    fn verify() {
        let msg: Message = SIWE.trim().parse().unwrap();
        assert!(
            Capability::<Value>::extract_and_verify(&msg)
                .transpose()
                .expect("unable to parse resources as capabilities")
                .is_ok(),
            "statement did not match capabilities"
        );

        let mut altered_msg_1 = msg.clone();
        altered_msg_1
            .statement
            .iter_mut()
            .for_each(|statement| statement.push_str(" I am the walrus!"));
        assert!(
            Capability::<Value>::extract_and_verify(&altered_msg_1).is_err(),
            "altered statement incorrectly matched capabilities"
        );
    }

    #[test]
    fn verify_interleaved_resources() {
        let msg: Message = SIWE_WITH_INTERLEAVED_RES.trim().parse().unwrap();
        assert!(
            Capability::<Value>::extract_and_verify(&msg)
                .unwrap()
                .is_none(),
            "recap resource should come last"
        );
    }
}
