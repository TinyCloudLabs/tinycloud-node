//! Holder recipients, as pinned in the node's `at_rest.escrow.recipients`.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::piv::PivRecipient;
use crate::{EscrowError, HOLDERS};

/// One escrow holder: a label and the age recipient their share is sealed to.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HolderRecipient {
    /// 1-32 chars of `a-z 0-9 - _`, unique within the escrow.
    pub holder: String,
    /// See [`RecipientKind`].
    pub recipient: String,
}

/// The recipient format. The format says which kind of key can decrypt; it
/// does not prove where the private key lives. That a P-256 key was made on
/// a YubiKey is established in the escrow ceremony, not here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecipientKind {
    /// `age1yubikey1…` (`piv-p256` stanza): what released age-plugin-yubikey
    /// prints and decrypts.
    PivP256,
    /// `age1tag1…` (`p256tag` stanza): native age tagged P-256 recipient,
    /// meant for hardware keys.
    P256Tag,
    /// `age1…` X25519: a software key file. Test and self-host only.
    X25519,
}

impl RecipientKind {
    pub fn is_software(self) -> bool {
        self == Self::X25519
    }
}

/// Which recipient kinds an escrow may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RecipientPolicy {
    /// P-256 key formats only (`age1yubikey1`, `age1tag1`). The default.
    #[default]
    HardwareOnly,
    /// Also X25519 software keys. Only for tests and self-hosted nodes that
    /// explicitly opt in; tools warn loudly whenever it is in effect.
    AllowSoftware,
}

pub(crate) enum ParsedRecipient {
    Piv(PivRecipient),
    Tag(age::tag::Recipient),
    X25519(age::x25519::Recipient),
}

impl ParsedRecipient {
    pub(crate) fn as_age(&self) -> &dyn age::Recipient {
        match self {
            Self::Piv(r) => r,
            Self::Tag(r) => r,
            Self::X25519(r) => r,
        }
    }

    fn kind(&self) -> RecipientKind {
        match self {
            Self::Piv(_) => RecipientKind::PivP256,
            Self::Tag(_) => RecipientKind::P256Tag,
            Self::X25519(_) => RecipientKind::X25519,
        }
    }
}

pub(crate) fn parse(holder: &str, recipient: &str) -> Result<ParsedRecipient, EscrowError> {
    let err = |reason: &str| EscrowError::Recipient {
        holder: holder.to_owned(),
        reason: reason.to_owned(),
    };
    if recipient.starts_with("age1yubikey1") {
        recipient
            .parse::<PivRecipient>()
            .map(ParsedRecipient::Piv)
            .map_err(err)
    } else if recipient.starts_with("age1tag1") {
        recipient
            .parse::<age::tag::Recipient>()
            .map(ParsedRecipient::Tag)
            .map_err(err)
    } else if recipient.starts_with("age1") {
        recipient
            .parse::<age::x25519::Recipient>()
            .map(ParsedRecipient::X25519)
            .map_err(err)
    } else {
        Err(err(
            "not an age1yubikey1, age1tag1 or age1 X25519 recipient",
        ))
    }
}

/// Parse one recipient and report its kind.
pub fn parse_recipient(holder: &str, recipient: &str) -> Result<RecipientKind, EscrowError> {
    parse(holder, recipient).map(|r| r.kind())
}

fn valid_holder_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Exactly three holders, valid unique names, unique recipients that parse,
/// and no software recipient unless `policy` allows it.
pub fn validate_holders(
    holders: &[HolderRecipient],
    policy: RecipientPolicy,
) -> Result<Vec<RecipientKind>, EscrowError> {
    if holders.len() != usize::from(HOLDERS) {
        return Err(EscrowError::Holders(format!(
            "need exactly {HOLDERS} holders, got {}",
            holders.len()
        )));
    }
    let mut names = HashSet::new();
    let mut recipients = HashSet::new();
    let mut kinds = Vec::with_capacity(holders.len());
    for h in holders {
        if !valid_holder_name(&h.holder) {
            return Err(EscrowError::Holders(format!(
                "holder name {:?} must be 1-32 chars of a-z 0-9 - _",
                h.holder
            )));
        }
        if !names.insert(h.holder.as_str()) {
            return Err(EscrowError::Holders(format!(
                "holder {:?} listed twice",
                h.holder
            )));
        }
        if !recipients.insert(h.recipient.as_str()) {
            return Err(EscrowError::Holders(format!(
                "holder {:?} reuses another holder's recipient",
                h.holder
            )));
        }
        let kind = parse_recipient(&h.holder, &h.recipient)?;
        if kind.is_software() && policy == RecipientPolicy::HardwareOnly {
            return Err(EscrowError::Recipient {
                holder: h.holder.clone(),
                reason: "X25519 recipients are software keys; use a YubiKey (age1yubikey1/age1tag1) or explicitly allow software recipients (tests and self-host only)".into(),
            });
        }
        kinds.push(kind);
    }
    Ok(kinds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{piv_identity, tag_identity, x25519_identity};

    fn holder(name: &str, recipient: String) -> HolderRecipient {
        HolderRecipient {
            holder: name.into(),
            recipient,
        }
    }

    #[test]
    fn reports_each_kind_and_refuses_software_by_default() {
        let holders = vec![
            holder("sam", piv_identity().1),
            holder("hunter", tag_identity().1),
            holder("safe", x25519_identity().to_public().to_string()),
        ];
        assert_eq!(
            validate_holders(&holders, RecipientPolicy::AllowSoftware).unwrap(),
            vec![
                RecipientKind::PivP256,
                RecipientKind::P256Tag,
                RecipientKind::X25519
            ]
        );
        let err = validate_holders(&holders, RecipientPolicy::HardwareOnly).unwrap_err();
        assert!(
            matches!(&err, EscrowError::Recipient { holder, .. } if holder == "safe"),
            "{err}"
        );
        let hardware = vec![
            holder("sam", piv_identity().1),
            holder("hunter", tag_identity().1),
            holder("safe", piv_identity().1),
        ];
        validate_holders(&hardware, RecipientPolicy::HardwareOnly).unwrap();
    }

    #[test]
    fn rejects_count_names_duplicates_and_bad_recipients() {
        let r = || piv_identity().1;
        let v = |h: &[HolderRecipient]| validate_holders(h, RecipientPolicy::AllowSoftware);
        assert!(v(&[holder("a", r()), holder("b", r())]).is_err());
        assert!(v(&[
            holder("a", r()),
            holder("b", r()),
            holder("c", r()),
            holder("d", r())
        ])
        .is_err());
        assert!(v(&[holder("a", r()), holder("a", r()), holder("c", r())]).is_err());
        assert!(v(&[holder("Sam", r()), holder("b", r()), holder("c", r())]).is_err());
        assert!(v(&[holder("", r()), holder("b", r()), holder("c", r())]).is_err());
        let same = r();
        assert!(v(&[
            holder("a", same.clone()),
            holder("b", same),
            holder("c", r())
        ])
        .is_err());
        for bad in [
            "age1yubikey1qwerty",
            "ssh-ed25519 AAAA",
            "age1notavalidrecipient",
            "age1tag1notvalid",
        ] {
            assert!(
                v(&[holder("a", bad.into()), holder("b", r()), holder("c", r())]).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn parses_a_real_age_plugin_yubikey_recipient() {
        // From age-plugin-yubikey 0.5.1 tests/integration.rs.
        let real = "age1yubikey1q2w7u3vpya839jxxuq8g0sedh3d740d4xvn639sqhr95ejj8vu3hyfumptt";
        assert_eq!(
            parse_recipient("sam", real).unwrap(),
            RecipientKind::PivP256
        );
    }
}
