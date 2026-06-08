use crate::cacaos::siwe::encode_eip55;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkhDid {
    pub chain_id: u64,
    pub address: String,
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    #[error("invalid EIP-155 address prefix")]
    InvalidAddressPrefix,
    #[error("invalid EIP-155 address length: expected 40, got {0}")]
    InvalidAddressLength(usize),
    #[error("invalid EIP-155 address character at {index}: {character}")]
    InvalidAddressChar { index: usize, character: char },
    #[error("invalid EIP-155 chain ID")]
    InvalidChainId,
    #[error("invalid did:pkh:eip155 DID")]
    InvalidPkhDid,
    #[error("invalid DID")]
    InvalidDid,
}

fn hex_nibble(index: usize, c: char) -> Result<u8, IdentityError> {
    match c {
        '0'..='9' => Ok(c as u8 - b'0'),
        'a'..='f' => Ok(c as u8 - b'a' + 10),
        'A'..='F' => Ok(c as u8 - b'A' + 10),
        _ => Err(IdentityError::InvalidAddressChar {
            index,
            character: c,
        }),
    }
}

pub fn canonicalize_eip155_address(address: &str) -> Result<String, IdentityError> {
    let raw = address
        .strip_prefix("0x")
        .ok_or(IdentityError::InvalidAddressPrefix)?;
    if raw.len() != 40 {
        return Err(IdentityError::InvalidAddressLength(raw.len()));
    }

    let mut bytes = [0u8; 20];
    let mut chars = raw.chars().enumerate();
    for byte in &mut bytes {
        let (hi_index, hi) = chars.next().ok_or(IdentityError::InvalidPkhDid)?;
        let (lo_index, lo) = chars.next().ok_or(IdentityError::InvalidPkhDid)?;
        *byte = (hex_nibble(hi_index, hi)? << 4) | hex_nibble(lo_index, lo)?;
    }

    Ok(format!("0x{}", encode_eip55(&bytes)))
}

pub fn parse_pkh_did(did: &str) -> Result<Option<PkhDid>, IdentityError> {
    let Some(rest) = did.strip_prefix("did:pkh:eip155:") else {
        return Ok(None);
    };
    let (chain_id, address) = rest.split_once(':').ok_or(IdentityError::InvalidPkhDid)?;
    if address.contains(':') {
        return Err(IdentityError::InvalidPkhDid);
    }
    let chain_id = chain_id
        .parse::<u64>()
        .ok()
        .filter(|id| *id > 0)
        .ok_or(IdentityError::InvalidChainId)?;

    Ok(Some(PkhDid {
        chain_id,
        address: canonicalize_eip155_address(address)?,
    }))
}

pub fn canonicalize_did(did: &str) -> Result<String, IdentityError> {
    if let Some(pkh) = parse_pkh_did(did)? {
        return Ok(format!("did:pkh:eip155:{}:{}", pkh.chain_id, pkh.address));
    }
    if did
        .strip_prefix("did:")
        .and_then(|rest| rest.split_once(':'))
        .is_some()
    {
        return Ok(did.to_string());
    }
    Err(IdentityError::InvalidDid)
}

pub fn canonicalize_did_url(did_url: &str) -> Result<String, IdentityError> {
    match did_url.split_once('#') {
        Some((did, fragment)) => Ok(format!("{}#{}", canonicalize_did(did)?, fragment)),
        None => canonicalize_did(did_url),
    }
}

pub fn principal_did(did_url: &str) -> Result<String, IdentityError> {
    let did = did_url.split_once('#').map_or(did_url, |(did, _)| did);
    canonicalize_did(did)
}

pub fn canonicalize_principal(principal: &str) -> Result<String, IdentityError> {
    if principal.starts_with("did:") {
        canonicalize_did(principal)
    } else {
        Ok(principal.to_string())
    }
}

pub fn did_principal_matches(actual: &str, expected: &str) -> bool {
    match (principal_did(actual), principal_did(expected)) {
        (Ok(a), Ok(b)) => a == b,
        _ => actual == expected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOWER: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    const CHECKSUM: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    #[test]
    fn canonicalizes_eip155_address() {
        assert_eq!(canonicalize_eip155_address(LOWER).unwrap(), CHECKSUM);
        assert_eq!(
            canonicalize_eip155_address("0xF39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap(),
            CHECKSUM
        );
    }

    #[test]
    fn canonicalizes_pkh_did() {
        assert_eq!(
            canonicalize_did(&format!("did:pkh:eip155:1:{LOWER}")).unwrap(),
            format!("did:pkh:eip155:1:{CHECKSUM}")
        );
        assert_eq!(
            parse_pkh_did(&format!("did:pkh:eip155:1:{LOWER}"))
                .unwrap()
                .unwrap(),
            PkhDid {
                chain_id: 1,
                address: CHECKSUM.to_string(),
            }
        );
    }

    #[test]
    fn preserves_other_did_methods() {
        assert_eq!(
            canonicalize_did("did:key:z6MkExampleAbcd").unwrap(),
            "did:key:z6MkExampleAbcd"
        );
        assert!(!did_principal_matches(
            "did:key:z6MkExampleAbcd",
            "did:key:z6MkExampleabcd"
        ));
    }

    #[test]
    fn canonicalizes_did_urls_and_principals() {
        assert_eq!(
            canonicalize_did_url(&format!("did:pkh:eip155:1:{LOWER}#controller")).unwrap(),
            format!("did:pkh:eip155:1:{CHECKSUM}#controller")
        );
        assert!(did_principal_matches(
            &format!("did:pkh:eip155:1:{LOWER}#controller"),
            &format!("did:pkh:eip155:1:{CHECKSUM}#other")
        ));
    }

    #[test]
    fn rejects_invalid_supported_pkh_dids() {
        assert_eq!(
            canonicalize_did("did:pkh:eip155:1:0x1234").unwrap_err(),
            IdentityError::InvalidAddressLength(4)
        );
    }
}
