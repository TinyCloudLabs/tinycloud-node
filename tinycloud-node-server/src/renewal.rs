pub use tinycloud_core::renewal::{
    new_end, period_seconds, validate_stamp_end, verify_stamp_signature, OriginalFormat,
    RenewalError, RenewalSigner, RENEWER_KEY_CONTEXT, STAMP_DOMAIN,
};

#[cfg(test)]
mod tests {
    use super::{
        new_end, period_seconds, validate_stamp_end, verify_stamp_signature, OriginalFormat,
        RenewalSigner, RENEWER_KEY_CONTEXT, STAMP_DOMAIN,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use tinycloud_core::keys::{Secrets, StaticSecret};

    #[test]
    fn frozen_domain_and_key_context_are_literal_contracts() {
        assert_eq!(STAMP_DOMAIN, "tinycloud/node/renewal-stamp/v1");
        assert_eq!(RENEWER_KEY_CONTEXT, b"tinycloud/node/renewer/v1");
    }

    #[test]
    fn period_uses_only_signed_original_anchor_and_cacao_issued_at_fallback() {
        assert_eq!(
            period_seconds(
                1_702_592_000,
                Some(1_700_000_000),
                None,
                OriginalFormat::Ucan
            )
            .unwrap(),
            2_592_000
        );
        assert_eq!(
            period_seconds(
                1_702_592_000,
                None,
                Some(1_700_000_000),
                OriginalFormat::Cacao
            )
            .unwrap(),
            2_592_000
        );
        assert!(period_seconds(
            1_702_592_000,
            None,
            Some(1_700_000_000),
            OriginalFormat::Ucan
        )
        .is_err());
        assert!(period_seconds(
            1_700_000_000,
            Some(1_700_000_000),
            None,
            OriginalFormat::Ucan
        )
        .is_err());
    }

    #[test]
    fn new_end_is_bounded_by_every_ancestor_as_well_as_lease_and_period() {
        let now = 1_702_000_000;
        let period = 2_592_000;
        let lease_expiry = 1_731_536_000;
        let ancestor_end = now + 100_000;
        assert_eq!(
            new_end(now, period, lease_expiry, &[ancestor_end]).unwrap(),
            ancestor_end
        );
        assert!(new_end(now, 0, lease_expiry, &[]).is_err());
    }

    #[test]
    fn stamp_bounds_are_checked_at_creation_and_acceptance() {
        let stamp_end = 1_702_100_000;
        let now = 1_702_000_000;
        let period = 2_592_000;
        assert!(
            validate_stamp_end(stamp_end, now, period, 1_731_536_000, &[1_702_200_000]).is_ok()
        );
        assert!(
            validate_stamp_end(stamp_end, now, period, 1_702_050_000, &[1_702_200_000]).is_err()
        );
        assert!(
            validate_stamp_end(stamp_end, now, period, 1_731_536_000, &[1_702_050_000]).is_err()
        );
        assert!(validate_stamp_end(now + period + 1, now, period, 1_731_536_000, &[]).is_err());
    }

    #[test]
    fn renewal_signer_is_the_lease_audience_key_not_the_stable_node_identity_key() {
        let node = StaticSecret::new(vec![0x42; 32]).unwrap();
        let signer = RenewalSigner::from_seed(node.renewal_seed().unwrap(), node.node_did());
        let (bytes, signature, _) = signer
            .sign_stamp("original", "lease", 1, "lease", "2024-01-12T22:13:20Z")
            .unwrap();
        assert_eq!(
            signer.public_key(),
            node.renewal_keypair()
                .public()
                .try_into_ed25519()
                .unwrap()
                .to_bytes()
        );
        verify_stamp_signature(&bytes, &signature, &signer.public_key()).unwrap();
        let node_public = node
            .node_keypair()
            .public()
            .try_into_ed25519()
            .unwrap()
            .to_bytes();
        assert!(verify_stamp_signature(&bytes, &signature, &node_public).is_err());
    }

    #[test]
    fn wrong_audience_key_rejects_a_stamp_signed_by_the_renewer() {
        let renewer = SigningKey::from_bytes(&[0x33; 32]);
        let node = SigningKey::from_bytes(&[0x44; 32]);
        let bytes = b"canonical renewal stamp bytes";
        let signature = renewer.sign(bytes);
        assert!(verify_stamp_signature(
            bytes,
            &signature.to_bytes(),
            &renewer.verifying_key().to_bytes()
        )
        .is_ok());
        assert!(verify_stamp_signature(
            bytes,
            &signature.to_bytes(),
            &node.verifying_key().to_bytes()
        )
        .is_err());
    }
}
