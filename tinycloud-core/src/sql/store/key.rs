//! SQL object keys (TC-1491 contract, section 3). Pure functions, no I/O.
//!
//! `sql/v1/{space_enc}/{db_enc}/{lineage}/snap/{at_seq:020}-{hash}` and
//! `.../seg/{base_seq:020}-{from_seq:020}-{to_seq:020}-{hash}`. Every key is a
//! pure function of its content and position, so it is immutable by
//! construction, and the alphabet is lowercase only so that it stays injective
//! on case-insensitive filesystems.

use std::fmt;

use rand::RngCore;

/// Root of the private SQL namespace. KV keys start with `tinycloud:`.
pub const KEY_ROOT: &str = "sql/v1/";
/// Longest `enc(x)` kept as-is; longer components use the hashed form.
const MAX_COMPONENT: usize = 255;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("space is empty")]
    EmptySpace,
    #[error("database id is empty")]
    EmptyDbId,
    #[error("sequence {0} does not fit a signed 64-bit column")]
    SeqOutOfRange(u64),
    #[error("segment range is invalid")]
    BadRange,
    #[error("not a canonical SQL object key")]
    NotCanonical,
}

/// The database a store entry belongs to: the physical artifact identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbRef<'a> {
    pub space: &'a str,
    pub db_id: &'a str,
}

macro_rules! hex128 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);
        impl $name {
            pub fn random() -> Self {
                let mut bytes = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut bytes);
                Self(hex::encode(bytes))
            }
            /// 32 lowercase hex characters, nothing else.
            pub fn parse(text: &str) -> Result<Self, KeyError> {
                if text.len() == 32 && text.bytes().all(is_lower_hex) {
                    Ok(Self(text.to_owned()))
                } else {
                    Err(KeyError::NotCanonical)
                }
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

hex128!(
    /// A history generation of one database's store copy: 128 random bits.
    Lineage
);
hex128!(
    /// Random per publish attempt, so a lost CAS response is reconciled exactly.
    PublishId
);

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

fn is_kept(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'
}

/// Escape one key component. Bytes in `[a-z0-9_-]` are kept; every other byte
/// (uppercase letters and `.` included) becomes `.` plus two lowercase hex
/// digits. A component whose escaped form is longer than 255 bytes becomes `~`
/// plus the SHA-256 of the raw bytes in hex; `~` is outside the alphabet, so
/// the two forms cannot collide.
pub fn enc(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        if is_kept(b) {
            out.push(b as char);
        } else {
            out.push('.');
            out.push_str(&hex::encode([b]));
        }
    }
    if out.len() > MAX_COMPONENT {
        use sha2::{Digest, Sha256};
        return format!("~{}", hex::encode(Sha256::digest(raw.as_bytes())));
    }
    out
}

/// Invert [`enc`] for the escaped form. Rejects anything `enc` cannot
/// produce: a stray `.`, uppercase hex, characters outside the alphabet, a
/// hashed (`~`) component (not reversible) or invalid UTF-8.
pub fn dec(encoded: &str) -> Result<String, KeyError> {
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if is_kept(b) {
            out.push(b);
            i += 1;
        } else if b == b'.' {
            let pair = bytes.get(i + 1..i + 3).ok_or(KeyError::NotCanonical)?;
            if !pair.iter().copied().all(is_lower_hex) {
                return Err(KeyError::NotCanonical);
            }
            let byte = u8::from_str_radix(
                std::str::from_utf8(pair).map_err(|_| KeyError::NotCanonical)?,
                16,
            )
            .map_err(|_| KeyError::NotCanonical)?;
            // A byte `enc` would have kept must not be escaped.
            if is_kept(byte) {
                return Err(KeyError::NotCanonical);
            }
            out.push(byte);
            i += 3;
        } else {
            return Err(KeyError::NotCanonical);
        }
    }
    String::from_utf8(out).map_err(|_| KeyError::NotCanonical)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectKind {
    Snapshot,
    Segment,
}

impl ObjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Segment => "segment",
        }
    }
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "snapshot" => Some(Self::Snapshot),
            "segment" => Some(Self::Segment),
            _ => None,
        }
    }
}

fn seq_ok(seq: u64) -> Result<u64, KeyError> {
    if seq > i64::MAX as u64 {
        Err(KeyError::SeqOutOfRange(seq))
    } else {
        Ok(seq)
    }
}

/// A validated SQL object key together with the fields it encodes. These are
/// also the columns of `sql_store_object`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectKey {
    key: String,
    lineage: Lineage,
    kind: ObjectKind,
    base_seq: u64,
    from_seq: u64,
    to_seq: u64,
    sha256: [u8; 32],
}

impl ObjectKey {
    /// A snapshot of the database as of `at_seq`.
    pub fn snapshot(
        db: &DbRef<'_>,
        lineage: &Lineage,
        at_seq: u64,
        sha256: &[u8; 32],
    ) -> Result<Self, KeyError> {
        seq_ok(at_seq)?;
        let prefix = lineage_prefix(db, lineage)?;
        Ok(Self {
            key: format!("{prefix}snap/{at_seq:020}-{}", hex::encode(sha256)),
            lineage: lineage.clone(),
            kind: ObjectKind::Snapshot,
            base_seq: at_seq,
            from_seq: at_seq,
            to_seq: at_seq,
            sha256: *sha256,
        })
    }

    /// Changes `from_seq..=to_seq` on top of the snapshot taken at `base_seq`.
    pub fn segment(
        db: &DbRef<'_>,
        lineage: &Lineage,
        base_seq: u64,
        from_seq: u64,
        to_seq: u64,
        sha256: &[u8; 32],
    ) -> Result<Self, KeyError> {
        seq_ok(base_seq)?;
        seq_ok(from_seq)?;
        seq_ok(to_seq)?;
        if from_seq <= base_seq || to_seq < from_seq {
            return Err(KeyError::BadRange);
        }
        let prefix = lineage_prefix(db, lineage)?;
        Ok(Self {
            key: format!(
                "{prefix}seg/{base_seq:020}-{from_seq:020}-{to_seq:020}-{}",
                hex::encode(sha256)
            ),
            lineage: lineage.clone(),
            kind: ObjectKind::Segment,
            base_seq,
            from_seq,
            to_seq,
            sha256: *sha256,
        })
    }

    /// `sql/v1/{space}/{db}/`: every object of one database, all lineages.
    pub fn db_prefix(db: &DbRef<'_>) -> Result<String, KeyError> {
        if db.space.is_empty() {
            return Err(KeyError::EmptySpace);
        }
        if db.db_id.is_empty() {
            return Err(KeyError::EmptyDbId);
        }
        Ok(format!("{KEY_ROOT}{}/{}/", enc(db.space), enc(db.db_id)))
    }

    pub fn as_str(&self) -> &str {
        &self.key
    }
    pub fn lineage(&self) -> &Lineage {
        &self.lineage
    }
    pub fn kind(&self) -> ObjectKind {
        self.kind
    }
    pub fn base_seq(&self) -> u64 {
        self.base_seq
    }
    pub fn from_seq(&self) -> u64 {
        self.from_seq
    }
    pub fn to_seq(&self) -> u64 {
        self.to_seq
    }
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
    pub fn content_hash(&self) -> String {
        hex::encode(self.sha256)
    }
}

impl fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.key)
    }
}

fn lineage_prefix(db: &DbRef<'_>, lineage: &Lineage) -> Result<String, KeyError> {
    Ok(format!("{}{lineage}/", ObjectKey::db_prefix(db)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;

    fn db<'a>(space: &'a str, db_id: &'a str) -> DbRef<'a> {
        DbRef { space, db_id }
    }

    const SPACE: &str =
        "tinycloud:pkh:eip155:1:0xAbC0000000000000000000000000000000000001://default";

    #[test]
    fn escaping_keeps_only_lowercase_alphabet() {
        assert_eq!(enc("abc_1-z"), "abc_1-z");
        assert_eq!(enc("A"), ".41");
        assert_eq!(enc("."), ".2e");
        assert_eq!(enc("a/b:c"), "a.2fb.3ac");
        assert!(enc(SPACE)
            .bytes()
            .all(|b| is_kept(b) || b == b'.' || b == b'~'));
        assert!(!enc(SPACE).contains('/'));
        assert!(!enc(SPACE).bytes().any(|b| b.is_ascii_uppercase()));
    }

    #[test]
    fn decoder_accepts_only_canonical_form() {
        for raw in ["", "a", "A", ".", "..", "a/b", "café", "v2dabc", SPACE] {
            assert_eq!(dec(&enc(raw)).unwrap(), raw);
        }
        for bad in [
            ".", ".4", ".4G", ".4A", ".41x/", "A", "a b", ".61", "~00", "a/b",
        ] {
            assert!(dec(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn dot_dot_cannot_occur() {
        for raw in [".", "..", "...", "a..b"] {
            let e = enc(raw);
            assert!(!e.contains(".."), "{e}");
            assert_ne!(e, ".");
        }
    }

    #[test]
    fn long_components_use_the_hashed_form() {
        let long = "A".repeat(100);
        let e = enc(&long);
        assert!(e.starts_with('~') && e.len() == 65);
        assert_ne!(e, enc(&"A".repeat(101)));
        assert!(dec(&e).is_err());
        // A raw component can never produce a `~`, so no escaped form collides.
        assert!(!enc("~").contains('~'));
    }

    #[test]
    fn keys_have_the_documented_shape() {
        let lineage = Lineage::parse(&"ab".repeat(16)).unwrap();
        let h = [7u8; 32];
        let snap = ObjectKey::snapshot(&db(SPACE, "v2dff"), &lineage, 5, &h).unwrap();
        assert!(snap.as_str().starts_with("sql/v1/"));
        assert!(snap
            .as_str()
            .ends_with(&format!("/{lineage}/snap/{:020}-{}", 5, hex::encode(h))));
        let seg = ObjectKey::segment(&db(SPACE, "v2dff"), &lineage, 5, 6, 9, &h).unwrap();
        assert!(seg.as_str().ends_with(&format!(
            "/seg/{:020}-{:020}-{:020}-{}",
            5,
            6,
            9,
            hex::encode(h)
        )));
        assert_eq!((seg.base_seq(), seg.from_seq(), seg.to_seq()), (5, 6, 9));
        assert!(ObjectKey::db_prefix(&db(SPACE, "v2dff"))
            .map(|p| snap.as_str().starts_with(&p))
            .unwrap());
    }

    #[test]
    fn invalid_inputs_are_rejected() {
        let l = Lineage::random();
        let h = [0u8; 32];
        assert_eq!(
            ObjectKey::snapshot(&db("", "x"), &l, 1, &h),
            Err(KeyError::EmptySpace)
        );
        assert_eq!(
            ObjectKey::snapshot(&db("s", ""), &l, 1, &h),
            Err(KeyError::EmptyDbId)
        );
        assert!(matches!(
            ObjectKey::snapshot(&db("s", "d"), &l, u64::MAX, &h),
            Err(KeyError::SeqOutOfRange(_))
        ));
        assert_eq!(
            ObjectKey::segment(&db("s", "d"), &l, 5, 5, 6, &h),
            Err(KeyError::BadRange)
        );
        assert_eq!(
            ObjectKey::segment(&db("s", "d"), &l, 5, 7, 6, &h),
            Err(KeyError::BadRange)
        );
        assert!(Lineage::parse("AB".repeat(16).as_str()).is_err());
        assert!(Lineage::parse("ab").is_err());
    }

    #[test]
    fn a_key_never_looks_like_a_kv_key() {
        // KV keys are `{space}/{b64}` and a space id starts with `tinycloud:`.
        let l = Lineage::random();
        let k = ObjectKey::snapshot(&db(SPACE, "d"), &l, 0, &[1; 32]).unwrap();
        assert!(!k.as_str().starts_with("tinycloud:"));
        assert!(k.as_str().starts_with(KEY_ROOT));
        // Even a hostile space or db id is escaped into one component.
        let hostile = ObjectKey::snapshot(&db("sql/v1/../x", "../.."), &l, 0, &[1; 32]).unwrap();
        assert!(!hostile.as_str().contains(".."));
        assert_eq!(
            hostile.as_str().matches('/').count(),
            k.as_str().matches('/').count()
        );
    }

    proptest! {
        #[test]
        fn enc_is_injective_and_reversible(a in ".{0,20}", b in ".{0,20}") {
            if a != b {
                prop_assert_ne!(enc(&a), enc(&b));
            }
            prop_assert_eq!(dec(&enc(&a)).unwrap(), a);
        }

        #[test]
        fn enc_is_injective_after_case_folding(a in "[A-Za-z0-9:/._-]{0,30}", b in "[A-Za-z0-9:/._-]{0,30}") {
            if a != b {
                prop_assert_ne!(enc(&a).to_ascii_lowercase(), enc(&b).to_ascii_lowercase());
            }
        }

        #[test]
        fn keys_are_injective_and_deterministic(
            s1 in "[A-Za-z0-9:/]{1,20}", d1 in "[A-Za-z0-9._-]{1,20}",
            s2 in "[A-Za-z0-9:/]{1,20}", d2 in "[A-Za-z0-9._-]{1,20}",
            seq1 in 0u64..1000, seq2 in 0u64..1000,
            h1 in any::<[u8; 32]>(), h2 in any::<[u8; 32]>(),
        ) {
            let l = Lineage::parse(&"0f".repeat(16)).unwrap();
            let k1 = ObjectKey::snapshot(&db(&s1, &d1), &l, seq1, &h1).unwrap();
            let k2 = ObjectKey::snapshot(&db(&s2, &d2), &l, seq2, &h2).unwrap();
            let same_inputs = (&s1, &d1, seq1, h1) == (&s2, &d2, seq2, h2);
            prop_assert_eq!(k1 == k2, same_inputs);
            prop_assert_eq!(k1.as_str() == k2.as_str(), same_inputs);
            // Case-insensitive collision: lowercased keys are equal iff inputs are.
            prop_assert_eq!(
                k1.as_str().eq_ignore_ascii_case(k2.as_str()),
                same_inputs
            );
            // A snapshot and a segment at the same coordinates never share a key.
            let seg = ObjectKey::segment(&db(&s1, &d1), &l, seq1, seq1 + 1, seq1 + 1, &h1).unwrap();
            prop_assert_ne!(seg.as_str(), k1.as_str());
        }
    }

    #[test]
    fn no_two_distinct_hostile_ids_collide() {
        let ids = [
            "a", "A", "a.", ".a", "a/b", "a.2fb", "a%2fb", "~", "~00", "", ".", "..",
        ];
        let set: HashSet<_> = ids.iter().map(|i| enc(i)).collect();
        assert_eq!(set.len(), ids.len());
        let folded: HashSet<_> = set.iter().map(|e| e.to_ascii_lowercase()).collect();
        assert_eq!(folded.len(), ids.len());
    }
}
