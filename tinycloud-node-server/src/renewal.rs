pub use tinycloud_core::renewal::{
    new_end, period_seconds, validate_stamp_end, verify_stamp_signature, OriginalFormat,
    RenewalError, RenewalSigner, RENEWER_KEY_CONTEXT, STAMP_DOMAIN,
};

use anyhow::{anyhow, Result};
use tinycloud_auth::{
    authorization::{make_invocation_from_uris, InvocationOptions, TinyCloudInvocation},
    ssi::jwk::{Algorithm, Base64urlUInt, OctetParams, Params, JWK},
};
use tinycloud_core::{
    events::Invocation,
    keys::StaticSecret,
    renewal::{self, LeaseRecord, StampIssue},
};

use std::future::Future;
pub(crate) const SCHEDULER_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);
const INVOCATION_LIFETIME_SECONDS: i64 = 300;

fn due_for_renewal(now: i64, end: i64, period_seconds: u64) -> bool {
    let horizon = now.saturating_add((period_seconds / 2).max(1).min(i64::MAX as u64) as i64);
    end <= horizon
}

fn renewal_invocation_signer(secret: &StaticSecret) -> Result<(JWK, String)> {
    let keypair = secret.renewal_keypair();
    let public_key = keypair
        .public()
        .try_into_ed25519()
        .map_err(|error| anyhow!("{error}"))?;
    let mut jwk = JWK::from(Params::OKP(OctetParams {
        curve: "Ed25519".to_owned(),
        public_key: Base64urlUInt(public_key.to_bytes().to_vec()),
        private_key: Some(Base64urlUInt(
            secret.derive_key(RENEWER_KEY_CONTEXT).to_vec(),
        )),
    }));
    jwk.algorithm = Some(Algorithm::EdDSA);
    let did = secret.renewal_did();
    let fragment = did
        .rsplit_once(':')
        .map(|(_, fragment)| fragment)
        .ok_or_else(|| anyhow!("renewal DID has no key fragment"))?;
    Ok((jwk, format!("{did}#{fragment}")))
}

fn build_scheduled_invocation(
    lease: &LeaseRecord,
    signer: &JWK,
    verification_method: &str,
    now: i64,
) -> Result<(TinyCloudInvocation, i64)> {
    let lease_cid = lease.lease_cid.parse()?;
    let expiry = now
        .checked_add(INVOCATION_LIFETIME_SECONDS)
        .ok_or_else(|| anyhow!("renewal invocation expiry overflow"))?;
    let invocation = make_invocation_from_uris(
        [(
            format!("urn:cid:{}", lease.original_cid).parse()?,
            ["tinycloud.delegation/renew".parse()?],
        )],
        &lease_cid,
        signer,
        verification_method,
        expiry as f64,
        InvocationOptions {
            nonce: Some(format!("urn:uuid:{}", uuid::Uuid::new_v4())),
            proof: Some(vec![lease_cid]),
            ..Default::default()
        },
    )?;
    Ok((invocation, expiry))
}

pub(crate) async fn scheduler_tick(
    tinycloud: &crate::TinyCloud,
    secret: &StaticSecret,
) -> Result<()> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let conn = tinycloud.connection();
    let identity = tinycloud
        .renewal_identity()
        .ok_or_else(|| anyhow!("node renewal identity is not initialized"))?;
    let leases = renewal::active_leases_for_current_epoch(conn, identity).await?;
    let (signer, verification_method) = renewal_invocation_signer(secret)?;
    for_each_scheduled_lease(leases, |lease| {
        let tinycloud = tinycloud;
        let conn = conn;
        let identity = identity;
        let signer = &signer;
        let verification_method = &verification_method;
        async move {
            if lease.state != "active" || lease.renewer_did != identity.renewer_did {
                return Ok(());
            }
            let Some(end) =
                renewal::effective_end(conn, &lease.original_cid, &lease.lease_cid, now, identity)
                    .await?
            else {
                return Ok(());
            };
            if !due_for_renewal(now, end, lease.period_seconds) {
                return Ok(());
            }
            let (signed, replay_expires_at) =
                build_scheduled_invocation(&lease, signer, verification_method, now)?;
            let encoded = signed.encode()?;
            let event = Invocation::from_header_ser::<TinyCloudInvocation>(&encoded)
                .map_err(|error| anyhow!("{error:?}"))?;
            let replay_hash = event.content_hash();
            let issue = StampIssue {
                invocation: event.0,
                original_cid: lease.original_cid,
                lease_cid: lease.lease_cid,
                replay_hash,
                replay_expires_at,
            };
            tinycloud.issue_renewal_stamp(issue).await?;
            Ok(())
        }
    })
    .await;
    Ok(())
}

async fn for_each_scheduled_lease<F, Fut>(leases: Vec<LeaseRecord>, mut process: F)
where
    F: FnMut(LeaseRecord) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    for lease in leases {
        if let Err(error) = process(lease).await {
            ::tracing::warn!(
                event = "renewal_scheduler_lease_failed",
                error = %error,
                "internal renewal scheduler failed for one lease; continuing"
            );
        }
    }
}

#[cfg(test)]
mod scheduler_tests {
    use super::{build_scheduled_invocation, due_for_renewal, renewal_invocation_signer};
    use tinycloud_core::{keys::StaticSecret, renewal::LeaseRecord, util::InvocationInfo};

    #[test]
    fn scheduler_builds_a_single_lease_bound_renewal_invocation() -> anyhow::Result<()> {
        let secret = StaticSecret::new(vec![0x73; 32]).unwrap();
        let expected_renewer_did = secret.renewal_did();
        let (signer, verification_method) = renewal_invocation_signer(&secret)?;
        let lease = LeaseRecord {
            original_cid: "bafkr4ibdtwxhoauccwuknmf7cd5m3o74rwek7al4wgs33ecoygubpmour4".to_owned(),
            lease_cid: "bafkr4ignh3iowa5gysgegtuosa62pdkw6mpvrhsr3umjey5x2zo4fvjgqq".to_owned(),
            grantor: "did:key:owner".to_owned(),
            renewer_did: expected_renewer_did.clone(),
            renewer_epoch: 7,
            lease_expiry: 2_000,
            period_seconds: 30,
            state: "active".to_owned(),
            generation: 1,
        };
        let (signed, expiry) =
            build_scheduled_invocation(&lease, &signer, &verification_method, 1_000)?;
        let info = InvocationInfo::try_from(signed)?;
        assert_eq!(info.invoker, expected_renewer_did);
        let fragment = lease.renewer_did.rsplit_once(':').unwrap().1;
        assert_eq!(
            verification_method,
            format!("{}#{fragment}", lease.renewer_did)
        );
        assert_eq!(info.parents.len(), 1);
        assert_eq!(info.parents[0].to_string(), lease.lease_cid);
        assert_eq!(info.capabilities.len(), 1);
        assert_eq!(
            info.capabilities[0].ability.as_ref().as_ref(),
            "tinycloud.delegation/renew"
        );
        assert_eq!(
            info.capabilities[0].resource.to_string(),
            format!("urn:cid:{}", lease.original_cid)
        );
        assert_eq!(expiry, 1_300);

        Ok(())
    }

    #[test]
    fn scheduler_waits_until_half_of_the_signed_period_remains() {
        assert!(!due_for_renewal(100, 116, 30));
        assert!(due_for_renewal(100, 115, 30));
        assert!(due_for_renewal(100, 101, 30));
        assert!(!due_for_renewal(100, 102, 1));
        assert!(due_for_renewal(100, 100, 1));
    }
    #[tokio::test]
    async fn scheduler_continues_after_a_lease_failure() {
        let lease = |original_cid: &str| LeaseRecord {
            original_cid: original_cid.to_owned(),
            lease_cid: "lease".to_owned(),
            grantor: "did:key:owner".to_owned(),
            renewer_did: "did:key:renewer".to_owned(),
            renewer_epoch: 1,
            lease_expiry: 2_000,
            period_seconds: 30,
            state: "active".to_owned(),
            generation: 1,
        };
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        super::for_each_scheduled_lease(vec![lease("bad"), lease("later")], {
            let seen = std::sync::Arc::clone(&seen);
            move |lease| {
                let seen = std::sync::Arc::clone(&seen);
                async move {
                    let fails = lease.original_cid == "bad";
                    seen.lock().unwrap().push(lease.original_cid);
                    if fails {
                        anyhow::bail!("invalid ancestor chain");
                    }
                    Ok(())
                }
            }
        })
        .await;
        assert_eq!(*seen.lock().unwrap(), ["bad", "later"]);
    }
}

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
        let signer = RenewalSigner::from_seed(node.renewal_seed().unwrap(), node.node_did(), 1);
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
