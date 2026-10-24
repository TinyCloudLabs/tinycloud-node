//! Parsing and containment for encryption resource identifiers.
//!
//! - `urn:tinycloud:encryption:<owner>:<network>` names a network ([`NetworkId`]).
//! - `urn:tinycloud:encryption:<owner>:<network>/<path>` names a key.
//! - `urn:tinycloud:encryption:<owner>:<network>/<path>/` names a key prefix.
//!
//! Paths are `/`-separated segments of `[a-z0-9][a-z0-9._-]*`.
//! Key and prefix networks are `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`; bare networks follow [`NetworkId`].
//!
//! The first path segment `apps` is reserved for deletable keys. A key under
//! it is `apps/<app id>/<name>[/<more>]` (at least three segments) and a prefix
//! is `apps/<app id>/[<more>/]` (at least two segments before the trailing
//! `/`). Every other path is a deterministic key.

use super::network_id::{NetworkId, NetworkIdError};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use tinycloud_auth::identity::{canonicalize_principal, did_principal_matches};

const PREFIX: &str = "urn:tinycloud:encryption:";
const MAX_PATH_BYTES: usize = 255;
const MAX_SEGMENTS: usize = 8;
const MAX_SEGMENT_BYTES: usize = 64;
/// First path segment reserved for deletable keys.
const APPS_SEGMENT: &str = "apps";
const MIN_APPS_KEY_SEGMENTS: usize = 3;
const MIN_APPS_PREFIX_SEGMENTS: usize = 2;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyIdError {
    #[error("missing urn:tinycloud:encryption: prefix")]
    MissingPrefix,
    #[error("invalid network identifier: {0}")]
    Network(#[from] NetworkIdError),
    #[error("missing owner/network separator")]
    MissingSeparator,
    #[error("invalid owner principal")]
    InvalidOwner,
    #[error("invalid network name")]
    InvalidNetwork,
    #[error("empty key path")]
    EmptyPath,
    #[error("key path exceeds 255 bytes")]
    PathTooLong,
    #[error("key path has more than 8 segments")]
    TooManySegments,
    #[error("invalid key path segment")]
    InvalidSegment,
    #[error(
        "a path under apps/ is apps/<app id>/<name> for a key and apps/<app id>/ for a prefix"
    )]
    AppsPathTooShort,
}

/// A key or key prefix under one network. `path` never has a trailing `/`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyLocation {
    owner: String,
    network: String,
    path: String,
}

impl KeyLocation {
    pub fn owner_did(&self) -> &str {
        &self.owner
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// The kind a key at this path has: a path under `apps/` is deletable,
    /// every other path is deterministic.
    pub fn kind(&self) -> KeyKind {
        KeyKind::for_path(&self.path)
    }

    fn same_network(&self, other: &Self) -> bool {
        self.owner == other.owner && self.network == other.network
    }

    /// Key location for `path` under `network`, validated with the same
    /// owner, network and path grammar as [`parse`].
    pub fn new(network: &NetworkId, path: &str) -> Result<Self, KeyIdError> {
        validate_owner(network.owner_did())?;
        validate_network(network.name())?;
        validate_path(path, false)?;
        Ok(Self {
            owner: network.owner_did().to_string(),
            network: network.name().to_string(),
            path: path.to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EncryptionResource {
    Network(NetworkId),
    Key(KeyLocation),
    KeyPrefix(KeyLocation),
}

impl EncryptionResource {
    pub fn owner_did(&self) -> &str {
        match self {
            Self::Network(id) => id.owner_did(),
            Self::Key(loc) | Self::KeyPrefix(loc) => loc.owner_did(),
        }
    }

    /// Whether `self` (granted) covers `requested`.
    ///
    /// A prefix covers keys strictly below it and prefixes at or below it.
    /// Networks and keys never cover each other.
    pub fn extends(&self, requested: &Self) -> bool {
        match (self, requested) {
            (Self::Network(a), Self::Network(b)) => a == b,
            (Self::Key(a), Self::Key(b)) => a == b,
            (Self::KeyPrefix(a), Self::Key(b)) => a.same_network(b) && is_below(&a.path, &b.path),
            (Self::KeyPrefix(a), Self::KeyPrefix(b)) => {
                a.same_network(b) && (a.path == b.path || is_below(&a.path, &b.path))
            }
            _ => false,
        }
    }
}

impl fmt::Display for EncryptionResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(id) => write!(f, "{id}"),
            Self::Key(loc) => write!(f, "{PREFIX}{}:{}/{}", loc.owner, loc.network, loc.path),
            Self::KeyPrefix(loc) => {
                write!(f, "{PREFIX}{}:{}/{}/", loc.owner, loc.network, loc.path)
            }
        }
    }
}

impl FromStr for EncryptionResource {
    type Err = KeyIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse(s)
    }
}

/// Parse an encryption resource identifier.
pub fn parse(input: &str) -> Result<EncryptionResource, KeyIdError> {
    let rest = input
        .strip_prefix(PREFIX)
        .ok_or(KeyIdError::MissingPrefix)?;
    let Some((scope, path)) = rest.split_once('/') else {
        return Ok(EncryptionResource::Network(NetworkId::from_str(input)?));
    };
    let (owner, network) = scope.rsplit_once(':').ok_or(KeyIdError::MissingSeparator)?;
    validate_owner(owner)?;
    validate_network(network)?;
    let (path, is_prefix) = match path.strip_suffix('/') {
        Some(stripped) => (stripped, true),
        None => (path, false),
    };
    validate_path(path, is_prefix)?;
    let location = KeyLocation {
        owner: owner.to_string(),
        network: network.to_string(),
        path: path.to_string(),
    };
    Ok(if is_prefix {
        EncryptionResource::KeyPrefix(location)
    } else {
        EncryptionResource::Key(location)
    })
}

/// Whether `uri` is a network, key, or prefix owned by `principal`.
/// Used for root authority: the owner of a key namespace is its root.
pub(crate) fn owned_by(uri: &str, principal: &str) -> bool {
    parse(uri).is_ok_and(|resource| did_principal_matches(resource.owner_did(), principal))
}

/// Whether `uri` names a key or a key prefix (not a bare network). A string
/// that does not parse as an encryption resource is not one.
pub fn is_named_key(uri: &str) -> bool {
    matches!(
        parse(uri),
        Ok(EncryptionResource::Key(_) | EncryptionResource::KeyPrefix(_))
    )
}

/// Whether keys at `path` are deletable (first segment exactly `apps`).
pub fn is_apps_path(path: &str) -> bool {
    path.split('/').next() == Some(APPS_SEGMENT)
}

/// The app id of a path under `apps/`: its second segment.
pub fn app_id_of(path: &str) -> Option<&str> {
    if !is_apps_path(path) {
        return None;
    }
    path.split('/').nth(1)
}

/// Key kind. A key's kind follows from its path alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyKind {
    /// Derived from the network secret and the path; never destroyed.
    Deterministic,
    /// Derived from the network secret, the path and a per-key random seed;
    /// destroyed by deleting the seed.
    Deletable,
}

impl KeyKind {
    pub fn for_path(path: &str) -> Self {
        if is_apps_path(path) {
            Self::Deletable
        } else {
            Self::Deterministic
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deterministic => "deterministic",
            Self::Deletable => "deletable",
        }
    }

    pub fn parse(stored: &str) -> Option<Self> {
        match stored {
            "deterministic" => Some(Self::Deterministic),
            "deletable" => Some(Self::Deletable),
            _ => None,
        }
    }
}

fn is_below(ancestor: &str, path: &str) -> bool {
    path.strip_prefix(ancestor)
        .is_some_and(|rest| rest.starts_with('/'))
}

fn validate_owner(owner: &str) -> Result<(), KeyIdError> {
    let mut parts = owner.splitn(3, ':');
    let (Some("did"), Some(method), Some(id)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(KeyIdError::InvalidOwner);
    };
    let method_ok = !method.is_empty()
        && method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let id_ok = !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'));
    if !(method_ok && id_ok) {
        return Err(KeyIdError::InvalidOwner);
    }
    match canonicalize_principal(owner) {
        Ok(canonical) if canonical == owner => Ok(()),
        _ => Err(KeyIdError::InvalidOwner),
    }
}

/// Maximum length of a network name inside a key or prefix.
const MAX_KEY_NETWORK_BYTES: usize = 64;

/// Key and prefix network names match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`.
fn validate_network(network: &str) -> Result<(), KeyIdError> {
    let bytes = network.as_bytes();
    let valid = bytes.len() <= MAX_KEY_NETWORK_BYTES
        && matches!(bytes.first(), Some(b) if b.is_ascii_alphanumeric())
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(KeyIdError::InvalidNetwork)
    }
}

/// Validates a key path (`is_prefix` false) or a prefix path without its
/// trailing `/` (`is_prefix` true).
fn validate_path(path: &str, is_prefix: bool) -> Result<(), KeyIdError> {
    if path.is_empty() {
        return Err(KeyIdError::EmptyPath);
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(KeyIdError::PathTooLong);
    }
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() > MAX_SEGMENTS {
        return Err(KeyIdError::TooManySegments);
    }
    if !segments.iter().all(|segment| valid_segment(segment)) {
        return Err(KeyIdError::InvalidSegment);
    }
    if is_apps_path(path) {
        let minimum = if is_prefix {
            MIN_APPS_PREFIX_SEGMENTS
        } else {
            MIN_APPS_KEY_SEGMENTS
        };
        if segments.len() < minimum {
            return Err(KeyIdError::AppsPathTooShort);
        }
    }
    Ok(())
}

pub(super) fn valid_segment(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    bytes.len() <= MAX_SEGMENT_BYTES
        && matches!(bytes.first(), Some(b) if b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.iter().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// Malformed key identifiers that the grammar must refuse.
#[cfg(test)]
pub(crate) const MALFORMED_KEY_IDS: [&str; 28] = [
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/apps/x//",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/apps//x",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default//apps",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/Apps/x",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/apps/../x",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/apps/./x",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/apps/a%2Fb",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/apps/a:b",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/apps/a b",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/apps/café",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/a/a/a/a/a/a/a/a/a",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/.hidden",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/-x",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:-default/apps/x",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/apps/",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/apps",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/apps/foo",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:.a/apps/x",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/apps/x",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/apps/x/a%2Fb",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/apps/x/a:b",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/apps/x/a b",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:default/apps/x/café",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:-default/apps/x/n",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:.a/apps/x/n",
    "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/apps/x/n",
];

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";

    fn uri(tail: &str) -> String {
        format!("{PREFIX}{OWNER}:{tail}")
    }

    fn segment(len: usize) -> String {
        "a".repeat(len)
    }

    fn key(path: &str) -> EncryptionResource {
        EncryptionResource::Key(KeyLocation {
            owner: OWNER.to_string(),
            network: "default".to_string(),
            path: path.to_string(),
        })
    }

    fn prefix(path: &str) -> EncryptionResource {
        EncryptionResource::KeyPrefix(KeyLocation {
            owner: OWNER.to_string(),
            network: "default".to_string(),
            path: path.to_string(),
        })
    }

    fn join(segments: &[String]) -> String {
        segments.join("/")
    }

    fn network() -> NetworkId {
        NetworkId::new(OWNER, "default").unwrap()
    }

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/encryption/app-key-vectors.json"
        ))
        .expect("vector file parses")
    }

    #[test]
    fn parses_network_key_and_prefix_forms() {
        assert!(matches!(
            parse(&uri("default")),
            Ok(EncryptionResource::Network(_))
        ));
        assert_eq!(
            parse(&uri("default/secrets/software-factory")),
            Ok(key("secrets/software-factory"))
        );
        assert_eq!(
            parse(&uri("default/apps/tinychat/")),
            Ok(prefix("apps/tinychat"))
        );
        assert_eq!(
            parse(&uri("default/apps/v1.2_x-y/n")),
            Ok(key("apps/v1.2_x-y/n"))
        );
        assert_eq!(parse(&uri("default/apps/x/")), Ok(prefix("apps/x")));
        assert_eq!(parse(&uri("default/apps/x/sub/")), Ok(prefix("apps/x/sub")));
    }

    #[test]
    fn accepts_did_key_did_web_and_mixed_case_network_owners() {
        let did_key = "urn:tinycloud:encryption:did:key:z6MkjHi79SMX4doJyo2w7jDTM6Fa7iX6EVZWXNbJ6RzBm3Wi:default/docs/tinychat";
        assert_eq!(
            parse(did_key).map(|r| r.owner_did().to_string()),
            Ok("did:key:z6MkjHi79SMX4doJyo2w7jDTM6Fa7iX6EVZWXNbJ6RzBm3Wi".to_string())
        );
        let did_web = "urn:tinycloud:encryption:did:web:example.com:user:alice:default/docs/x";
        assert_eq!(
            parse(did_web).map(|r| r.owner_did().to_string()),
            Ok("did:web:example.com:user:alice".to_string())
        );
        assert!(matches!(
            parse(&format!("{PREFIX}{OWNER}:Default/docs/x")),
            Ok(EncryptionResource::Key(loc)) if loc.network() == "Default"
        ));
    }

    #[test]
    fn accepts_maximum_path_and_segment_lengths() {
        let segments: Vec<String> = (0..8).map(|_| segment(31)).collect();
        let path = join(&segments);
        assert_eq!(path.len(), 255);
        assert_eq!(parse(&uri(&format!("default/{path}"))), Ok(key(&path)));
        // The trailing slash of a prefix is not counted against the limit.
        assert_eq!(parse(&uri(&format!("default/{path}/"))), Ok(prefix(&path)));

        let longest = segment(64);
        assert_eq!(
            parse(&uri(&format!("default/{longest}"))),
            Ok(key(&longest))
        );
    }

    #[test]
    fn bare_network_with_lowercase_owner_normalizes_owner() {
        let lower = "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed:default";
        match parse(lower) {
            Ok(EncryptionResource::Network(id)) => assert_eq!(id.owner_did(), OWNER),
            other => panic!("expected network, got {other:?}"),
        }
    }

    #[test]
    fn canonical_forms_round_trip() {
        for input in [
            uri("default"),
            uri("default/secrets/software-factory"),
            uri("default/apps/tinychat/"),
            uri("default/apps/v1.2_x-y/n"),
            uri("default/apps/x/"),
            format!("{PREFIX}{OWNER}:Default/apps/x/n"),
        ] {
            assert_eq!(parse(&input).unwrap().to_string(), input);
        }
    }

    #[test]
    fn rejects_malformed_identifiers() {
        let nine_segments = join(&(0..9).map(|_| segment(1)).collect::<Vec<_>>());
        let segments_256: Vec<String> = std::iter::once(segment(32))
            .chain((0..7).map(|_| segment(31)))
            .collect();
        let path_256 = join(&segments_256);
        assert_eq!(path_256.len(), 256);

        let cases = [
            // empty prefix (vector 22)
            uri("default/"),
            // owner not canonical (vector 23)
            "urn:tinycloud:encryption:did:pkh:eip155:1:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed:default/docs/x".to_string(),
            // `#` in owner, `#` and `?` in network, `%` in owner (vectors 25-28)
            "urn:tinycloud:encryption:did:key:z6MkjHi79SMX4doJyo2w7jDTM6Fa7iX6EVZWXNbJ6RzBm3Wi#x:default/docs/x".to_string(),
            uri("default#x/docs/x"),
            uri("default?x/docs/x"),
            "urn:tinycloud:encryption:did:web:example.com%3A8443:default/docs/x".to_string(),
            // path grammar (vectors 7-16, 20, 21)
            uri("default/docs/x//"),
            uri("default/docs//x"),
            uri("default//docs"),
            uri("default/Docs/x"),
            uri("default/docs/../x"),
            uri("default/docs/./x"),
            uri("default/docs/a%2Fb"),
            uri("default/docs/a:b"),
            uri("default/docs/a b"),
            uri("default/docs/café"),
            uri("default/.hidden"),
            uri("default/-x"),
            // count and length limits (vectors 17-19, 34)
            uri(&format!("default/{nine_segments}")),
            uri(&format!("default/{}", segment(65))),
            uri(&format!("default/{path_256}")),
            uri(&format!("default/{path_256}/")),
            // uppercase scheme or namespace is not the encryption namespace (vectors 29, 30)
            format!("URN:tinycloud:encryption:{OWNER}:default/docs/x"),
            format!("urn:TinyCloud:encryption:{OWNER}:default/docs/x"),
        ];
        for input in cases {
            assert!(parse(&input).is_err(), "accepted: {input}");
        }
    }

    /// Key and prefix networks outside `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` are refused.
    #[test]
    fn rejects_network_names_outside_the_key_network_class() {
        let longer_than_64 = "a".repeat(65);
        let cases = [
            // bidi override, key and prefix
            uri("de\u{202e}fault/docs/x"),
            uri("de\u{202e}fault/docs/x/"),
            // zero-width space and byte-order mark
            uri("de\u{200b}fault/docs/x"),
            uri("\u{feff}default/docs/x"),
            // control character and non-ASCII letter
            uri("de\u{7}fault/docs/x"),
            uri("d\u{e9}fault/docs/x"),
            // leading `-` and `.`
            uri("-default/docs/x"),
            uri(".a/docs/x"),
            // longer than 64 characters
            uri(&format!("{longer_than_64}/docs/x")),
            // newline inside the network, and newline after the path
            uri("default\n/docs/x"),
            uri("default/docs/x\n"),
        ];
        for input in cases {
            assert!(parse(&input).is_err(), "accepted: {input:?}");
        }
    }

    #[test]
    fn accepts_network_names_at_the_class_boundaries() {
        let longest = "a".repeat(64);
        for network in [longest.as_str(), "DeFault", "0.x_-y"] {
            match parse(&uri(&format!("{network}/docs/x"))) {
                Ok(EncryptionResource::Key(loc)) => assert_eq!(loc.network(), network),
                other => panic!("expected key for {network:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn bare_networks_keep_the_network_id_rule() {
        let longer_than_64 = "a".repeat(65);
        assert!(matches!(
            parse(&uri(&longer_than_64)),
            Ok(EncryptionResource::Network(_))
        ));
    }

    #[test]
    fn prefix_covers_keys_and_prefixes_strictly_below_it() {
        let granted = parse(&uri("default/docs/")).unwrap();
        assert!(granted.extends(&parse(&uri("default/docs/foo/")).unwrap()));
        assert!(granted.extends(&parse(&uri("default/docs/foo/bar")).unwrap()));
        assert!(!granted.extends(&parse(&uri("default/docs")).unwrap()));
    }

    #[test]
    fn containment_matches_contract_pairs() {
        let p = |tail: &str| parse(&uri(tail)).unwrap();
        // granted does not cover requested
        assert!(!p("default/apps/foo/").extends(&p("default/apps/foobar/x")));
        assert!(!p("default/docs/foo/").extends(&p("default/docs/foo")));
        assert!(!p("default").extends(&p("default/docs/x")));
        assert!(!p("default/docs/x").extends(&p("default")));
        // granted covers requested
        assert!(p("default/docs/").extends(&p("default/docs/foo/")));
        assert!(p("default/apps/foo/").extends(&p("default/apps/foo/a/b")));
        assert!(p("default/apps/foo/").extends(&p("default/apps/foo/a/")));
    }

    #[test]
    fn keys_and_networks_never_cover_each_other() {
        let p = |tail: &str| parse(&uri(tail)).unwrap();
        assert!(!p("default").extends(&p("default/docs/x")));
        assert!(p("default").extends(&p("default")));
        assert!(p("default/docs/x").extends(&p("default/docs/x")));
        assert!(!p("default/docs/x").extends(&p("default/docs/y")));
    }

    #[test]
    fn prefix_does_not_cover_other_owner_or_network() {
        let other_owner = parse(
            "urn:tinycloud:encryption:did:key:z6MkjHi79SMX4doJyo2w7jDTM6Fa7iX6EVZWXNbJ6RzBm3Wi:default/docs/x",
        )
        .unwrap();
        let granted = parse(&uri("default/docs/")).unwrap();
        assert!(!granted.extends(&other_owner));

        let other_network = parse(&uri("other/docs/x")).unwrap();
        assert!(!granted.extends(&other_network));
    }

    #[test]
    fn owned_by_checks_owner_of_any_encryption_resource() {
        assert!(owned_by(&uri("default/docs/x"), OWNER));
        assert!(owned_by(&uri("default/docs/"), OWNER));
        assert!(owned_by(&uri("default"), OWNER));
        assert!(!owned_by(
            &uri("default/docs/x"),
            "did:key:z6MkjHi79SMX4doJyo2w7jDTM6Fa7iX6EVZWXNbJ6RzBm3Wi"
        ));
        assert!(!owned_by("urn:tinycloud:encryption:default/docs/x", OWNER));
    }

    // Reserved-segment depth rule.

    #[test]
    fn apps_paths_need_an_app_id_and_a_name() {
        for refused in ["apps", "apps/foo"] {
            assert!(
                parse(&uri(&format!("default/{refused}"))).is_err(),
                "key accepted: {refused}"
            );
            assert!(
                KeyLocation::new(&network(), refused).is_err(),
                "location accepted: {refused}"
            );
        }
        for refused in ["apps/", "apps//"] {
            assert!(
                parse(&uri(&format!("default/{refused}"))).is_err(),
                "prefix accepted: {refused}"
            );
        }
        assert_eq!(
            KeyLocation::new(&network(), "apps").unwrap_err(),
            KeyIdError::AppsPathTooShort
        );
        assert!(parse(&uri("default/apps/foo/x")).is_ok());
        assert!(parse(&uri("default/apps/foo/")).is_ok());
        assert!(parse(&uri("default/apps/foo/x/")).is_ok());
    }

    #[test]
    fn only_the_exact_first_segment_apps_is_reserved() {
        for ordinary in ["appsx/y", "apps.x/y", "app/y", "xapps/y/z", "docs/apps"] {
            assert!(
                parse(&uri(&format!("default/{ordinary}"))).is_ok(),
                "refused: {ordinary}"
            );
            assert_eq!(KeyKind::for_path(ordinary), KeyKind::Deterministic);
        }
        assert!(parse(&uri("default/appsx/")).is_ok());
        assert!(parse(&uri("default/apps.x/")).is_ok());
        assert_eq!(KeyKind::for_path("apps/foo/x"), KeyKind::Deletable);
    }

    #[test]
    fn key_kind_follows_the_path() {
        let loc = |path: &str| KeyLocation::new(&network(), path).unwrap();
        assert_eq!(loc("apps/foo/x").kind(), KeyKind::Deletable);
        assert_eq!(loc("apps/foo/x/y").kind(), KeyKind::Deletable);
        assert_eq!(loc("docs/a").kind(), KeyKind::Deterministic);
        assert_eq!(loc("appsx/y").kind(), KeyKind::Deterministic);
        assert_eq!(app_id_of("apps/foo/x"), Some("foo"));
        assert_eq!(app_id_of("apps"), None);
        assert_eq!(app_id_of("appsx/y"), None);
        assert_eq!(KeyKind::parse("deletable"), Some(KeyKind::Deletable));
        assert_eq!(KeyKind::parse("seeded"), None);
    }

    #[test]
    fn shared_vectors_key_paths_under_apps() {
        let vectors = vectors();
        let cases = vectors["nodeKeyPathUnderApps"].as_array().unwrap();
        assert_eq!(cases.len(), 10);
        for case in cases {
            let path = case["keyPath"].as_str().unwrap();
            let accepted = case["accepted"].as_bool().unwrap();
            assert_eq!(
                KeyLocation::new(&network(), path).is_ok(),
                accepted,
                "location {path:?}"
            );
            assert_eq!(
                matches!(
                    parse(&uri(&format!("default/{path}"))),
                    Ok(EncryptionResource::Key(_))
                ),
                accepted,
                "parsed key {path:?}"
            );
        }
    }

    #[test]
    fn shared_vectors_paths_refused_by_the_key_grammar() {
        let vectors = vectors();
        let cases = vectors["keyPathsRefusedByGrammar"].as_array().unwrap();
        assert_eq!(cases.len(), 4);
        for case in cases {
            let path = case["keyPath"].as_str().unwrap();
            assert!(
                KeyLocation::new(&network(), path).is_err(),
                "accepted as a key path: {path:?}"
            );
        }
    }

    #[test]
    fn shared_vectors_prefix_validity() {
        let vectors = vectors();
        let cases = vectors["prefixValid"].as_array().unwrap();
        assert_eq!(cases.len(), 9);
        for case in cases {
            let prefix_path = case["prefix"].as_str().unwrap();
            let valid = case["valid"].as_bool().unwrap();
            let parsed = parse(&uri(&format!("default/{prefix_path}")));
            assert_eq!(
                matches!(parsed, Ok(EncryptionResource::KeyPrefix(_))),
                valid,
                "prefix {prefix_path:?}"
            );
        }
    }

    /// A prefix covers a key by plain byte prefix on grammar-valid paths only:
    /// a key path the grammar refuses is never covered.
    #[test]
    fn shared_vectors_prefix_coverage() {
        let vectors = vectors();
        let cases = vectors["prefixCovers"].as_array().unwrap();
        assert_eq!(cases.len(), 15);
        for case in cases {
            let granted = case["prefix"].as_str().unwrap();
            let requested = case["key"].as_str().unwrap();
            let covers = case["covers"].as_bool().unwrap();
            let granted_resource = parse(&uri(&format!("default/{granted}")))
                .unwrap_or_else(|e| panic!("prefix {granted:?} refused: {e}"));
            let actual = match parse(&uri(&format!("default/{requested}"))) {
                Ok(requested) => granted_resource.extends(&requested),
                Err(_) => false,
            };
            assert_eq!(actual, covers, "{granted:?} vs {requested:?}");
        }
    }

    #[test]
    fn only_an_app_prefix_reaches_keys_under_the_reserved_segment() {
        let reserved_key = parse(&uri("default/apps/foo/x")).unwrap();
        assert!(parse(&uri("default/apps/")).is_err());
        assert!(parse(&uri("default/")).is_err());
        assert!(!parse(&uri("default/appsx/"))
            .unwrap()
            .extends(&reserved_key));
        assert!(parse(&uri("default/apps/foo/"))
            .unwrap()
            .extends(&reserved_key));
        assert!(!parse(&uri("default/apps/bar/"))
            .unwrap()
            .extends(&reserved_key));
    }

    #[test]
    fn every_malformed_id_is_refused() {
        for id in MALFORMED_KEY_IDS {
            assert!(parse(id).is_err(), "accepted: {id}");
        }
    }

    #[test]
    fn app_keys_and_networks_never_cover_each_other() {
        let p = |tail: &str| parse(&uri(tail)).unwrap();
        assert!(!p("default").extends(&p("default/apps/foo/x")));
        assert!(!p("default").extends(&p("default/apps/foo/")));
        assert!(!p("default/apps/foo/x").extends(&p("default")));
        assert!(!p("default/apps/foo/").extends(&p("default")));
        assert!(p("default/apps/foo/x").extends(&p("default/apps/foo/x")));
        assert!(!p("default/apps/foo/x").extends(&p("default/apps/foo/y")));
    }

    #[test]
    fn an_app_prefix_does_not_cover_another_owner_or_network() {
        let other_owner = parse(
            "urn:tinycloud:encryption:did:key:z6MkjHi79SMX4doJyo2w7jDTM6Fa7iX6EVZWXNbJ6RzBm3Wi:default/apps/foo/x",
        )
        .unwrap();
        let granted = parse(&uri("default/apps/foo/")).unwrap();
        assert!(!granted.extends(&other_owner));
        assert!(!granted.extends(&parse(&uri("other/apps/foo/x")).unwrap()));
        assert!(!granted.extends(&parse(&uri("other/apps/foo/")).unwrap()));
        assert!(owned_by(&uri("default/apps/foo/x"), OWNER));
        assert!(owned_by(&uri("default/apps/foo/"), OWNER));
        assert!(!owned_by(
            &uri("default/apps/foo/x"),
            "did:key:z6MkjHi79SMX4doJyo2w7jDTM6Fa7iX6EVZWXNbJ6RzBm3Wi"
        ));
    }
}
