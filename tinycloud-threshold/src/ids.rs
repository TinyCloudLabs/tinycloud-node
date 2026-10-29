//! Bounded identifiers used in the version-one encodings.

use core::num::NonZeroU16;

use crate::error::Error;

/// A Shamir evaluation coordinate in the supported range `1..=16`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct MemberIndex(NonZeroU16);

impl MemberIndex {
    /// Reject zero and indices beyond the maximum cohort size.
    pub fn new(value: u16) -> Result<Self, Error> {
        if value > 16 {
            return Err(Error::InvalidIndex);
        }
        NonZeroU16::new(value).map(Self).ok_or(Error::InvalidIndex)
    }

    /// Return the nonzero evaluation coordinate.
    pub fn get(&self) -> u16 {
        self.0.get()
    }
}

/// A threshold and cohort size satisfying `2 <= t <= n <= 16`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Threshold {
    t: u16,
    n: u16,
}

impl Threshold {
    /// Validate a threshold for decryption and resharing.
    pub fn new(t: u16, n: u16) -> Result<Self, Error> {
        if t < 2 || t > n || n > 16 {
            return Err(Error::InvalidThreshold);
        }
        Ok(Self { t, n })
    }

    /// Return the number of distinct shares needed.
    pub fn t(&self) -> u16 {
        self.t
    }

    /// Return the cohort size.
    pub fn n(&self) -> u16 {
        self.n
    }

    /// Require the additional genesis-DKG condition `n >= 2t - 1`.
    ///
    /// A threshold valid for resharing need not satisfy this condition.
    pub fn check_genesis_budget(&self) -> Result<(), Error> {
        let required = self
            .t
            .checked_sub(1)
            .and_then(|faults| self.t.checked_add(faults))
            .ok_or(Error::UnsupportedFaultBudget)?;
        if self.n < required {
            return Err(Error::UnsupportedFaultBudget);
        }
        Ok(())
    }
}

macro_rules! text_id {
    ($name:ident, $cap:literal, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name(String);

        impl $name {
            /// Preserve the supplied UTF-8 exactly, rejecting empty or oversized values.
            ///
            /// Limits are measured in bytes; no normalization or syntax rewriting is applied.
            pub fn new(value: impl Into<String>) -> Result<Self, Error> {
                let value = value.into();
                if value.is_empty() {
                    return Err(Error::InvalidLength);
                }
                if value.len() > $cap {
                    return Err(Error::LimitExceeded);
                }
                Ok(Self(value))
            }

            /// Borrow the exact supplied text.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Borrow the exact UTF-8 representation.
            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }
        }
    };
}

text_id!(
    NetworkUrn,
    1024,
    "A network URN containing 1 through 1024 UTF-8 bytes."
);
text_id!(
    KeyPath,
    1024,
    "A key path containing 1 through 1024 UTF-8 bytes."
);
text_id!(Did, 256, "A DID containing 1 through 256 UTF-8 bytes.");

macro_rules! counter {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name(u64);

        impl $name {
            /// Construct a counter with its exact numeric value.
            pub fn new(value: u64) -> Self {
                Self(value)
            }

            /// Return the numeric value.
            pub fn get(&self) -> u64 {
                self.0
            }

            /// Increment by one, refusing to wrap at `u64::MAX`.
            pub fn checked_next(&self) -> Result<Self, Error> {
                self.0
                    .checked_add(1)
                    .map(Self)
                    .ok_or(Error::CounterOverflow)
            }
        }
    };
}

counter!(Epoch, "A monotonically increasing key epoch.");
counter!(
    RekeyCounter,
    "A counter incremented when the master key changes."
);
counter!(
    KeyVersion,
    "The application-supplied version of an identity's key path."
);

macro_rules! fixed_id {
    ($name:ident, $length:literal, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name([u8; $length]);

        impl $name {
            /// Construct from the exact fixed-width representation.
            pub fn new(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }

            /// Borrow the fixed-width representation.
            pub fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }
        }
    };
}

fixed_id!(WriteNonce, 16, "A record identity's per-write nonce.");
fixed_id!(CertDigest, 32, "A network-certificate digest.");
fixed_id!(TranscriptHash, 32, "A ceremony transcript hash.");
fixed_id!(RequestDigest, 32, "A decryption-request digest.");
fixed_id!(CeremonyId, 32, "A ceremony's fixed-width identifier.");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_indices_and_threshold_limits() {
        assert_eq!(MemberIndex::new(0), Err(Error::InvalidIndex));
        assert_eq!(MemberIndex::new(17), Err(Error::InvalidIndex));
        assert_eq!(MemberIndex::new(u16::MAX), Err(Error::InvalidIndex));
        for i in 1..=16 {
            assert_eq!(MemberIndex::new(i).unwrap().get(), i);
        }
        for (t, n) in [(0, 3), (1, 3), (4, 3), (2, 17), (16, u16::MAX)] {
            assert_eq!(Threshold::new(t, n), Err(Error::InvalidThreshold));
        }
        for n in 2..=16 {
            for t in 2..=n {
                let threshold = Threshold::new(t, n).unwrap();
                assert_eq!((threshold.t(), threshold.n()), (t, n));
                assert_eq!(threshold.check_genesis_budget().is_ok(), n >= 2 * t - 1);
            }
        }
        assert_eq!(
            Threshold::new(3, 4).unwrap().check_genesis_budget(),
            Err(Error::UnsupportedFaultBudget)
        );
        assert_eq!(Threshold::new(3, 5).unwrap().check_genesis_budget(), Ok(()));
    }

    #[test]
    fn text_limits_are_utf8_byte_limits_without_normalization() {
        assert_eq!(NetworkUrn::new(""), Err(Error::InvalidLength));
        assert_eq!(KeyPath::new(""), Err(Error::InvalidLength));
        assert_eq!(Did::new(""), Err(Error::InvalidLength));
        assert_eq!(NetworkUrn::new("n".repeat(1025)), Err(Error::LimitExceeded));
        assert_eq!(KeyPath::new("p".repeat(1025)), Err(Error::LimitExceeded));
        assert_eq!(Did::new("d".repeat(257)), Err(Error::LimitExceeded));
        assert!(NetworkUrn::new("é".repeat(512)).is_ok());
        assert_eq!(KeyPath::new("é".repeat(513)), Err(Error::LimitExceeded));
        assert!(Did::new("é".repeat(128)).is_ok());
        assert_eq!(Did::new("é".repeat(129)), Err(Error::LimitExceeded));
        let path = KeyPath::new("a/../b\0").unwrap();
        assert_eq!(path.as_str(), "a/../b\0");
        assert_eq!(path.as_bytes(), b"a/../b\0");
        assert_eq!(NetworkUrn::new("n").unwrap().as_str(), "n");
        assert_eq!(Did::new("d").unwrap().as_bytes(), b"d");
    }

    #[test]
    fn counters_increment_and_refuse_overflow() {
        assert_eq!(Epoch::new(0).checked_next().unwrap().get(), 1);
        assert_eq!(RekeyCounter::new(7).checked_next().unwrap().get(), 8);
        assert_eq!(KeyVersion::new(42).checked_next().unwrap().get(), 43);
        assert_eq!(
            Epoch::new(u64::MAX).checked_next(),
            Err(Error::CounterOverflow)
        );
        assert_eq!(
            RekeyCounter::new(u64::MAX).checked_next(),
            Err(Error::CounterOverflow)
        );
        assert_eq!(
            KeyVersion::new(u64::MAX).checked_next(),
            Err(Error::CounterOverflow)
        );
    }

    #[test]
    fn fixed_identifiers_preserve_every_byte() {
        assert_eq!(WriteNonce::new([0xff; 16]).as_bytes(), &[0xff; 16]);
        assert_eq!(CertDigest::new([1; 32]).as_bytes(), &[1; 32]);
        assert_eq!(TranscriptHash::new([2; 32]).as_bytes(), &[2; 32]);
        assert_eq!(RequestDigest::new([3; 32]).as_bytes(), &[3; 32]);
        assert_eq!(CeremonyId::new([4; 32]).as_bytes(), &[4; 32]);
    }
}

#[cfg(test)]
mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn arbitrary_indices_and_thresholds_match_bounds(index in any::<u16>(), t in any::<u16>(), n in any::<u16>()) {
            prop_assert_eq!(MemberIndex::new(index).is_ok(), (1..=16).contains(&index));
            prop_assert_eq!(Threshold::new(t, n).is_ok(), (2..=16).contains(&t) && t <= n && n <= 16);
        }

        #[test]
        fn arbitrary_counters_use_checked_increment(value in any::<u64>()) {
            let expected = value.checked_add(1);
            prop_assert_eq!(Epoch::new(value).checked_next().ok().map(|v| v.get()), expected);
            prop_assert_eq!(RekeyCounter::new(value).checked_next().ok().map(|v| v.get()), expected);
            prop_assert_eq!(KeyVersion::new(value).checked_next().ok().map(|v| v.get()), expected);
        }
    }
}
