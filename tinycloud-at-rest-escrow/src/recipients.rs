//! Holder recipients, as pinned in the node's `at_rest.escrow.recipients`.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{EscrowError, HOLDERS};

/// One escrow holder: a label and the age recipient their share is sealed to.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HolderRecipient {
    /// 1-32 chars of `a-z 0-9 - _`, unique within the escrow.
    pub holder: String,
    /// `age1tag1…` (P-256 hardware key, e.g. a YubiKey via age-plugin-yubikey)
    /// or `age1…` (X25519, software; tests and self-host only).
    pub recipient: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecipientKind {
    /// `age1tag1…` (`p256tag` stanza). Meant for keys held in hardware; age
    /// encrypts to it natively, decryption needs the holder's plugin.
    HardwareTag,
    /// `age1…` X25519. The identity is a file, not hardware.
    SoftwareX25519,
}

pub(crate) enum ParsedRecipient {
    Tag(age::tag::Recipient),
    X25519(age::x25519::Recipient),
}

impl ParsedRecipient {
    pub(crate) fn as_age(&self) -> &dyn age::Recipient {
        match self {
            Self::Tag(r) => r,
            Self::X25519(r) => r,
        }
    }
}

pub(crate) fn parse(holder: &str, recipient: &str) -> Result<ParsedRecipient, EscrowError> {
    let err = |reason: &str| EscrowError::Recipient {
        holder: holder.to_owned(),
        reason: reason.to_owned(),
    };
    if recipient.starts_with("age1tag1") {
        recipient
            .parse::<age::tag::Recipient>()
            .map(ParsedRecipient::Tag)
            .map_err(err)
    } else if recipient.starts_with("age1yubikey1") {
        Err(err(
            "age1yubikey1 recipients need the plugin to encrypt; use the age1tag1 form of the same key",
        ))
    } else if recipient.starts_with("age1") {
        recipient
            .parse::<age::x25519::Recipient>()
            .map(ParsedRecipient::X25519)
            .map_err(err)
    } else {
        Err(err("not an age1tag1 or age1 X25519 recipient"))
    }
}

/// Parse one recipient and report its kind.
pub fn parse_recipient(holder: &str, recipient: &str) -> Result<RecipientKind, EscrowError> {
    Ok(match parse(holder, recipient)? {
        ParsedRecipient::Tag(_) => RecipientKind::HardwareTag,
        ParsedRecipient::X25519(_) => RecipientKind::SoftwareX25519,
    })
}

fn valid_holder_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Exactly three holders, valid unique names, unique recipients that parse.
pub fn validate_holders(holders: &[HolderRecipient]) -> Result<Vec<RecipientKind>, EscrowError> {
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
        kinds.push(parse_recipient(&h.holder, &h.recipient)?);
    }
    Ok(kinds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{tag_identity, x25519_identity};

    fn holder(name: &str, recipient: String) -> HolderRecipient {
        HolderRecipient {
            holder: name.into(),
            recipient,
        }
    }

    #[test]
    fn accepts_tag_and_x25519_and_reports_kind() {
        let holders = vec![
            holder("sam", tag_identity().1),
            holder("hunter", tag_identity().1),
            holder("safe", x25519_identity().to_public().to_string()),
        ];
        assert_eq!(
            validate_holders(&holders).unwrap(),
            vec![
                RecipientKind::HardwareTag,
                RecipientKind::HardwareTag,
                RecipientKind::SoftwareX25519
            ]
        );
    }

    #[test]
    fn rejects_count_names_duplicates_and_bad_recipients() {
        let r = || x25519_identity().to_public().to_string();
        assert!(validate_holders(&[holder("a", r()), holder("b", r())]).is_err());
        assert!(validate_holders(&[
            holder("a", r()),
            holder("b", r()),
            holder("c", r()),
            holder("d", r())
        ])
        .is_err());
        assert!(validate_holders(&[holder("a", r()), holder("a", r()), holder("c", r())]).is_err());
        assert!(
            validate_holders(&[holder("Sam", r()), holder("b", r()), holder("c", r())]).is_err()
        );
        assert!(validate_holders(&[holder("", r()), holder("b", r()), holder("c", r())]).is_err());
        let same = r();
        assert!(validate_holders(&[
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
            let err =
                validate_holders(&[holder("a", bad.into()), holder("b", r()), holder("c", r())]);
            assert!(err.is_err(), "{bad}");
        }
    }
}
