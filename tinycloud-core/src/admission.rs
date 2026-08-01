//! TC-409: a single, non-forgeable admission boundary for public invocations.
//!
//! `/invoke` used to verify an invocation's envelope (time window +
//! signature) once at the route, then verify it again inside
//! `invocation::process`/`verify_and_authorize` during execution. The first
//! verification is load-bearing — it is what makes the durable replay
//! insert safe to trust — the second was pure duplicated DID-resolution and
//! signature-check work.
//!
//! [`AdmittedInvocation`] closes that gap: it can only be constructed by
//! [`AdmittedInvocation::admit`], which performs the exact verification the
//! route used to do inline. Holding one proves the envelope was checked
//! once; it proves nothing about authorization. Every core entry point that
//! accepts an admitted value re-runs authorization, revocation, caveat
//! containment, chain guards, and storage checks against the current
//! database state, and re-checks signed time validity to close the
//! admission-to-execution TOCTOU window.
use crate::events::Invocation;
use crate::models::invocation;
use time::OffsetDateTime;

/// Proof that an invocation's envelope (time window + signature) was
/// verified exactly once. Private field, no `Default`, no `Serialize`/
/// `Deserialize`, and no way to construct one except [`Self::admit`] — a
/// caller without a validly-signed, in-window, in-lifetime-cap invocation
/// cannot produce a value of this type, so it cannot be forged, decoded
/// from a request body, or reused across requests.
#[derive(Debug)]
pub struct AdmittedInvocation(Invocation);

#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error(transparent)]
    Invocation(#[from] invocation::Error),
    #[error("Invocation lifetime exceeds server maximum")]
    LifetimeExceeded,
}

impl AdmittedInvocation {
    /// The sole constructor. Runs the same time-window check and signature
    /// verification `invocation::verify_invocation` always ran (unchanged
    /// DID-resolution timeout and error mapping), then enforces the
    /// configured server lifetime cap. Only the value returned here may
    /// skip signature verification downstream.
    pub async fn admit(
        invocation: Invocation,
        max_lifetime_secs: u64,
    ) -> Result<Self, AdmissionError> {
        // AC5: this is the sole cryptographic verifier call on the
        // successful `/invoke` path. `InvocationSignatureVerify` must
        // surround exactly this call — not the lifetime-cap check below,
        // and not replay work, which stays separately attributable under
        // `ReplayCheck` in the durable replay adapter.
        let verify_start = std::time::Instant::now();
        let verify_result = invocation::verify_invocation(&invocation.0.invocation).await;
        crate::telemetry::observe_stage(
            crate::telemetry::InvocationStage::InvocationSignatureVerify,
            crate::telemetry::StageOutcome::from(verify_result.is_ok()),
            verify_start.elapsed(),
        );
        verify_result?;

        let now = OffsetDateTime::now_utc();
        if invocation.0.invocation.payload().expiration.as_seconds()
            > now.unix_timestamp() as f64 + max_lifetime_secs as f64
        {
            return Err(AdmissionError::LifetimeExceeded);
        }

        Ok(Self(invocation))
    }

    /// Borrow the admitted invocation for read-only routing decisions
    /// (capability inspection, caveat derivation, response bookkeeping).
    /// A shared reference cannot be used to reconstruct an
    /// `AdmittedInvocation` from unverified data.
    pub fn invocation(&self) -> &Invocation {
        &self.0
    }

    /// Hand the verified invocation to a core admitted entry point
    /// (`invocation::process_admitted`, `invocation::authorize_admitted`),
    /// or the durable replay insert. Crate-private: outside
    /// `tinycloud-core`, the only way to use an `AdmittedInvocation` is to
    /// pass it whole to one of the `*_admitted` APIs exposed on
    /// [`crate::db::SpaceDatabase`].
    pub(crate) fn into_invocation(self) -> Invocation {
        self.0
    }
}

/// TC-409 acceptance: a deterministic, opt-in hook that counts cryptographic
/// envelope verifications for a single, explicitly-armed invocation
/// identity. It exists purely so tests can assert "a successful request
/// invokes the cryptographic verifier exactly once". Gated behind
/// `#[cfg(any(test, feature = "verification-count-test-hook"))]`: the
/// feature is off by default and not requested by the normal
/// `tinycloud-core` dependency edge, so this code never exists in a
/// production binary. `tinycloud-node-server` enables the feature only for
/// `tinycloud-core` as a *dev*-dependency (see its `Cargo.toml`), which
/// makes the hook available to node route tests without ever compiling it
/// into `cargo build`/`cargo run`.
///
/// The counter is recorded at `invocation::verify_invocation` itself — the
/// single cryptographic-verification primitive shared by every envelope
/// check path (`process`, `verify_and_authorize`, and
/// `AdmittedInvocation::admit`) — not at any one caller. That means an
/// accidental extra call to the verifier from a different path (e.g. a
/// regression that re-verifies an already-admitted invocation during
/// execution) is counted too, which is the exact regression this hook
/// exists to catch.
///
/// `record` only ever increments an identity that a test has explicitly
/// `arm` first: it never inserts a new entry for an identity it
/// has not seen armed. That keeps unrelated invocations — from concurrent
/// tests sharing the same process/thread pool, or from production traffic
/// if the feature were ever mistakenly enabled — from occupying tracked
/// slots, so a selected identity's count can never be evicted or diluted by
/// unrelated activity, and the map stays bounded by the number of
/// concurrently *armed* identities rather than by all invocations observed
/// process-wide.
#[cfg(any(test, feature = "verification-count-test-hook"))]
pub mod test_hook {
    use crate::hash::Hash;
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    /// Hard cap on distinct identities armed at once. Only explicitly-armed
    /// identities ever take a slot (see module docs), so in practice this is
    /// far larger than the number of tests that use this hook concurrently;
    /// it exists purely so arming can never grow the map without bound.
    const MAX_ARMED_IDENTITIES: usize = 64;

    fn counts() -> &'static Mutex<HashMap<Hash, u64>> {
        static COUNTS: OnceLock<Mutex<HashMap<Hash, u64>>> = OnceLock::new();
        COUNTS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Record one cryptographic envelope verification for `identity`. A
    /// no-op unless `identity` was previously armed with `arm` — this is
    /// what stops unrelated invocations from other tests (or, in principle,
    /// production traffic) from ever occupying a tracked slot.
    pub fn record(identity: Hash) {
        let mut map = counts().lock().expect("verification-count hook mutex");
        if let Some(count) = map.get_mut(&identity) {
            *count += 1;
        }
    }

    /// Number of times `verify_invocation` has run for the invocation whose
    /// identity is `identity`, since it was armed by the last `arm`.
    /// Always `0` for an identity that was never armed.
    pub fn count_for(identity: Hash) -> u64 {
        counts()
            .lock()
            .expect("verification-count hook mutex")
            .get(&identity)
            .copied()
            .unwrap_or(0)
    }

    /// Arm `identity` for tracking, starting its count at zero. Call this
    /// immediately before exercising the call path under test, and again
    /// afterwards to disarm it. Only armed identities are ever recorded
    /// (see module docs), so this is the sole way an identity's slot is
    /// created — `record` never inserts one on its own.
    pub fn arm(identity: Hash) {
        let mut map = counts().lock().expect("verification-count hook mutex");
        assert!(
            map.len() < MAX_ARMED_IDENTITIES || map.contains_key(&identity),
            "verification-count hook capacity exceeded"
        );
        map.insert(identity, 0);
    }

    /// Stop tracking `identity` and release its bounded slot. Tests call this
    /// after their assertion so parallel or later tests cannot inherit stale
    /// armed identities or counts.
    pub fn disarm(identity: Hash) {
        counts()
            .lock()
            .expect("verification-count hook mutex")
            .remove(&identity);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tinycloud_auth::{
        resolver::DID_METHODS,
        ssi::{
            claims::jwt::NumericDate,
            dids::DIDURLBuf,
            jwk::{Algorithm, JWK},
            ucan::Payload,
        },
        ucan_capabilities_object::Capabilities,
    };

    /// Build a validly-signed, in-window invocation with no capabilities.
    /// Sufficient for exercising the admission envelope check (signature +
    /// time window), which does not inspect capabilities.
    fn signed_invocation(nonce: &str, expires_in_secs: f64) -> Invocation {
        let mut jwk = JWK::generate_ed25519().expect("generate key");
        jwk.algorithm = Some(Algorithm::EdDSA);
        let mut verification_method = DID_METHODS.generate(&jwk, "key").expect("did").to_string();
        let fragment = verification_method
            .rsplit_once(':')
            .expect("fragment")
            .1
            .to_string();
        verification_method.push('#');
        verification_method.push_str(&fragment);
        let issuer_did = verification_method
            .split('#')
            .next()
            .expect("issuer did")
            .to_string();

        let now = OffsetDateTime::now_utc();
        let payload = Payload {
            issuer: verification_method.parse::<DIDURLBuf>().expect("issuer"),
            audience: issuer_did.parse().expect("audience"),
            not_before: None,
            expiration: NumericDate::try_from_seconds(
                now.unix_timestamp() as f64 + expires_in_secs,
            )
            .expect("expiration"),
            nonce: Some(nonce.to_string()),
            facts: Some(Vec::new()),
            proof: vec![],
            attenuation: Capabilities::new(),
        }
        .sign(Algorithm::EdDSA, &jwk)
        .expect("sign invocation");

        let encoded = payload.encode().expect("encode invocation");
        let info = crate::util::InvocationInfo::try_from(payload).expect("invocation info");
        crate::events::SerializedEvent(info, encoded.into_bytes())
    }

    /// The test hook records against the invocation's nonce (see
    /// `verify_invocation`), not its content hash — arm/query with the same
    /// derivation the hook itself uses.
    fn nonce_identity(nonce: &str) -> crate::hash::Hash {
        crate::hash::hash(nonce.as_bytes())
    }

    #[tokio::test]
    async fn admit_records_exactly_one_verification_per_successful_call() {
        let nonce = "urn:uuid:admission-exactly-once";
        let invocation = signed_invocation(nonce, 30.0);
        let identity = nonce_identity(nonce);
        test_hook::arm(identity);

        AdmittedInvocation::admit(invocation, 300)
            .await
            .expect("validly-signed, in-window invocation is admitted");

        assert_eq!(
            test_hook::count_for(identity),
            1,
            "a single successful admission must record exactly one envelope verification"
        );

        test_hook::disarm(identity);
    }

    #[tokio::test]
    async fn admit_rejects_lifetime_beyond_server_cap_after_verifying_once() {
        let nonce = "urn:uuid:admission-over-cap";
        let invocation = signed_invocation(nonce, 3600.0);
        let identity = nonce_identity(nonce);
        test_hook::arm(identity);

        let err = AdmittedInvocation::admit(invocation, 300)
            .await
            .expect_err("expiration beyond the server cap must be rejected");
        assert!(matches!(err, AdmissionError::LifetimeExceeded));

        // The cryptographic verifier already ran (and succeeded) before the
        // lifetime cap rejected admission — the hook counts verifier calls,
        // not full admission successes, so this must be 1, not 0.
        assert_eq!(
            test_hook::count_for(identity),
            1,
            "the verifier runs (and is counted) before the lifetime cap is checked"
        );

        test_hook::disarm(identity);
    }
}
