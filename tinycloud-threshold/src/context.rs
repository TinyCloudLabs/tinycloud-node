//! Key-context commitments and the node's capability-check boundary.

use crate::derive::DecryptRequest;
use crate::dst::{tagged_hash, KEY_CONTEXT};
use crate::encoding::Encoder;
use crate::error::Error;
use crate::identity::IbeIdentity;
use crate::ids::{CertDigest, Epoch, KeyPath, KeyVersion, NetworkUrn, RekeyCounter, Threshold};

/// A key context established by the crate's certificate path.
///
/// There is no public production constructor. Certificate verification supplies
/// these fields; the test-only dealer uses a constructor absent from production.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyContext {
    pub(crate) network: NetworkUrn,
    pub(crate) rekey: RekeyCounter,
    pub(crate) epoch: Epoch,
    pub(crate) certificate: CertDigest,
    pub(crate) threshold: Threshold,
}

impl KeyContext {
    /// Hash the frozen version-one context body under its dedicated tag.
    pub fn digest(&self) -> [u8; 32] {
        tagged_hash(KEY_CONTEXT, &self.encode())
    }

    /// Encode version, network, generation, certificate, and threshold in order.
    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.u8(1);
        encoder.lp(self.network.as_bytes());
        encoder.u64(self.rekey.get());
        encoder.u64(self.epoch.get());
        encoder.fixed(self.certificate.as_bytes());
        encoder.u16(self.threshold.t());
        encoder.u16(self.threshold.n());
        encoder.finish()
    }

    /// Borrow the context's network.
    pub fn network(&self) -> &NetworkUrn {
        &self.network
    }

    /// Return the counter incremented when the master key changes.
    pub fn rekey(&self) -> RekeyCounter {
        self.rekey
    }

    /// Return the monotonically increasing epoch.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Borrow the certificate digest bound to this context.
    pub fn certificate(&self) -> &CertDigest {
        &self.certificate
    }

    /// Return the threshold and cohort size.
    pub fn threshold(&self) -> Threshold {
        self.threshold
    }

    #[cfg(test)]
    pub(crate) fn test(
        network: NetworkUrn,
        rekey: RekeyCounter,
        epoch: Epoch,
        certificate: CertDigest,
        threshold: Threshold,
    ) -> Self {
        Self {
            network,
            rekey,
            epoch,
            certificate,
            threshold,
        }
    }
}

/// A request paired with the identity tuple authorized by the node.
///
/// This is a node assertion, not a certificate or an independent authorization
/// check. Its only public constructor checks the supplied authorized tuple
/// against the request's complete, rebuilt identity bytes.
pub struct AuthorizedDerivation {
    pub(crate) request: DecryptRequest,
}

impl AuthorizedDerivation {
    /// Construct only after the node's capability check authorized exactly
    /// `(authorized_urn, authorized_path, version)` for this caller.
    ///
    /// The request's record/session mode and record nonce are preserved when
    /// rebuilding the identity. Any mismatch returns `UnauthorizedIdentity`.
    pub fn from_capability_check(
        request: DecryptRequest,
        authorized_urn: &NetworkUrn,
        authorized_path: &KeyPath,
        version: KeyVersion,
    ) -> Result<Self, Error> {
        let rebuilt = match request.identity.nonce() {
            Some(nonce) => IbeIdentity::record(authorized_urn, authorized_path, version, nonce)?,
            None => IbeIdentity::session(authorized_urn, authorized_path, version)?,
        };
        if rebuilt.as_bytes() != request.identity.as_bytes() {
            return Err(Error::UnauthorizedIdentity);
        }
        Ok(Self { request })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::{DecryptRequest, TransportSecretKey};
    use crate::identity::IbeIdentity;
    use crate::ids::WriteNonce;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use sha2::{Digest, Sha256};

    fn context() -> KeyContext {
        KeyContext::test(
            NetworkUrn::new("net").unwrap(),
            RekeyCounter::new(4),
            Epoch::new(9),
            CertDigest::new([3; 32]),
            Threshold::new(2, 3).unwrap(),
        )
    }

    fn request(record: bool) -> DecryptRequest {
        let ctx = context();
        let path = KeyPath::new("path").unwrap();
        let id = if record {
            IbeIdentity::record(
                ctx.network(),
                &path,
                KeyVersion::new(7),
                &WriteNonce::new([9; 16]),
            )
            .unwrap()
        } else {
            IbeIdentity::session(ctx.network(), &path, KeyVersion::new(7)).unwrap()
        };
        let mut rng = ChaCha20Rng::from_seed([11; 32]);
        DecryptRequest::new(
            &ctx,
            id,
            TransportSecretKey::generate(&mut rng).public_key(),
        )
        .unwrap()
    }

    #[test]
    fn context_frozen_body_digest_and_getters() {
        let ctx = context();
        let mut expected = vec![1, 0, 0, 0, 3, b'n', b'e', b't'];
        expected.extend_from_slice(&4u64.to_be_bytes());
        expected.extend_from_slice(&9u64.to_be_bytes());
        expected.extend_from_slice(&[3; 32]);
        expected.extend_from_slice(&[0, 2, 0, 3]);
        assert_eq!(ctx.encode(), expected);
        let tag = b"TC-THRESHOLD-V1-KEY-CONTEXT";
        let mut hash = Sha256::new();
        hash.update((tag.len() as u32).to_be_bytes());
        hash.update(tag);
        hash.update(&expected);
        assert_eq!(ctx.digest(), <[u8; 32]>::from(hash.finalize()));
        assert_eq!(ctx.network().as_str(), "net");
        assert_eq!(ctx.rekey(), RekeyCounter::new(4));
        assert_eq!(ctx.epoch(), Epoch::new(9));
        assert_eq!(ctx.certificate(), &CertDigest::new([3; 32]));
        assert_eq!(ctx.threshold(), Threshold::new(2, 3).unwrap());
    }

    #[test]
    fn context_digest_binds_every_field() {
        let ctx = context();
        let mut mutations = Vec::new();
        let mut changed = ctx.clone();
        changed.network = NetworkUrn::new("other").unwrap();
        mutations.push(changed);
        let mut changed = ctx.clone();
        changed.rekey = RekeyCounter::new(5);
        mutations.push(changed);
        let mut changed = ctx.clone();
        changed.epoch = Epoch::new(10);
        mutations.push(changed);
        let mut changed = ctx.clone();
        changed.certificate = CertDigest::new([4; 32]);
        mutations.push(changed);
        let mut changed = ctx.clone();
        changed.threshold = Threshold::new(3, 3).unwrap();
        mutations.push(changed);
        let mut changed = ctx.clone();
        changed.threshold = Threshold::new(2, 4).unwrap();
        mutations.push(changed);
        for changed in mutations {
            assert_ne!(ctx.digest(), changed.digest());
        }
    }

    #[test]
    fn capability_check_binds_exact_authorized_tuple_preserving_mode_and_nonce() {
        for record in [false, true] {
            let req = request(record);
            let expected_identity = req.identity().clone();
            let auth = AuthorizedDerivation::from_capability_check(
                req,
                &NetworkUrn::new("net").unwrap(),
                &KeyPath::new("path").unwrap(),
                KeyVersion::new(7),
            )
            .unwrap();
            assert_eq!(auth.request.identity(), &expected_identity);
            for (network, path, version) in [
                ("other", "path", 7),
                ("net", "other", 7),
                ("net", "path", 8),
            ] {
                assert!(matches!(
                    AuthorizedDerivation::from_capability_check(
                        request(record),
                        &NetworkUrn::new(network).unwrap(),
                        &KeyPath::new(path).unwrap(),
                        KeyVersion::new(version)
                    ),
                    Err(Error::UnauthorizedIdentity)
                ));
            }
        }
    }
}
